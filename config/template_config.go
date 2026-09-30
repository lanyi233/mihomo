package config

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/sprig/v3"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/age"
	C "github.com/metacubex/mihomo/constant"
	"github.com/shoobyban/json5"
)

const maxTemplateOutput = 8 << 20

const templateCommandTimeout = 30 * time.Second

const maxTemplateCommandError = 64 << 10

type TemplateData struct {
	System SystemTemplateData
}

type SystemTemplateData struct {
	OS   string
	Arch string
}

func newTemplateData() TemplateData {
	return TemplateData{System: SystemTemplateData{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}}
}

func templateFuncMap() template.FuncMap {
	funcs := sprig.TxtFuncMap()
	funcs["env"] = func(name string) (string, error) {
		value, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("environment variable %q is not set", name)
		}
		return value, nil
	}
	funcs["expandenv"] = func(value string) (string, error) {
		var missing string
		expanded := os.Expand(value, func(name string) string {
			value, ok := os.LookupEnv(name)
			if !ok && missing == "" {
				missing = name
			}
			return value
		})
		if missing != "" {
			return "", fmt.Errorf("environment variable %q is not set", missing)
		}
		return expanded, nil
	}
	funcs["cmd"] = runTemplateCommand
	funcs["cat"] = templateCat
	funcs["fromJson"] = templateFromJSON
	funcs["fromYaml"] = templateFromYAML
	funcs["fromToml"] = templateFromTOML
	return funcs
}

// templateCat implements the cat template function. It returns the contents of
// the requested files concatenated together, so a template can inline other
// documents, for example {{ cat "subconfig/*.yaml" }}.
//
// Relative paths resolve against the directory of the configuration file
// instead of the process working directory, which keeps templates independent
// from where mihomo was started. Glob patterns keep shell semantics, plus a
// ** segment matches zero or more directory levels like GitHub Actions
// workflow path rules do. Directories are skipped, and a missing file or an
// empty match is an error so a broken include never renders a partial
// configuration.
func templateCat(paths ...string) (string, error) {
	if len(paths) == 0 {
		return "", fmt.Errorf("cat requires at least one file path")
	}
	var out strings.Builder
	endsWithNewline := true
	for _, path := range paths {
		matches, err := expandTemplateCatPath(path)
		if err != nil {
			return "", err
		}
		for _, match := range matches {
			content, err := readTemplateFile(match)
			if err != nil {
				return "", err
			}
			if out.Len() > 0 && !endsWithNewline {
				// Keep every included document on its own line so files
				// without a trailing newline cannot merge YAML lines.
				out.WriteByte('\n')
				endsWithNewline = true
			}
			if out.Len()+len(content) > maxTemplateOutput {
				return "", fmt.Errorf("cat output exceeds 8 MiB")
			}
			out.WriteString(content)
			if content != "" {
				endsWithNewline = strings.HasSuffix(content, "\n")
			}
		}
	}
	return out.String(), nil
}

// expandTemplateCatPath resolves one cat argument to a list of readable files.
// Relative paths are anchored at the configuration file directory, plain shell
// globs are expanded by filepath.Glob and a pattern containing ** recurses into
// subdirectories. Directories are dropped: cat only reads files.
func expandTemplateCatPath(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("cat file path is empty")
	}
	pattern := path
	if filepath.IsAbs(pattern) {
		pattern = filepath.Clean(pattern)
	} else {
		pattern = filepath.Join(filepath.Dir(C.Path.Config()), pattern)
	}
	var matches []string
	var err error
	if strings.Contains(pattern, "**") {
		matches, err = globTemplateRecursive(pattern)
	} else {
		matches, err = filepath.Glob(pattern)
	}
	if err != nil {
		return nil, fmt.Errorf("cat %q: %w", path, err)
	}
	files := filterTemplateFiles(matches)
	if len(files) == 0 {
		if strings.ContainsAny(path, "*?[") {
			return nil, fmt.Errorf("cat: no file matched %q", path)
		}
		if info, statErr := os.Stat(pattern); statErr == nil && info.IsDir() {
			return nil, fmt.Errorf("cat: %q is a directory", path)
		}
		return nil, fmt.Errorf("cat: file %q not found", path)
	}
	return files, nil
}

// filterTemplateFiles keeps only existing non-directory entries, so an include
// never fails because a directory matched a pattern. Duplicates produced by
// overlapping recursive expansions are removed.
func filterTemplateFiles(paths []string) []string {
	files := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		files = append(files, path)
	}
	return files
}

// globTemplateRecursive expands a pattern that contains the ** wildcard. A **
// path segment stands for zero or more directory levels, so "subconfig/**"
// covers the directory itself and everything below it, while every other
// segment keeps plain shell glob behaviour. Paths are handled in slash form
// internally and returned with the platform separator.
func globTemplateRecursive(pattern string) ([]string, error) {
	root, segments := splitTemplateGlobRoot(pattern)
	candidates := []string{root}
	for _, segment := range segments {
		switch {
		case segment == "**":
			candidates = expandTemplateRecursiveSegment(candidates)
		case !strings.ContainsAny(segment, "*?["):
			joined := make([]string, 0, len(candidates))
			for _, candidate := range candidates {
				joined = append(joined, strings.TrimSuffix(candidate, "/")+"/"+segment)
			}
			candidates = joined
		default:
			expanded, err := expandTemplateMetaSegment(candidates, segment)
			if err != nil {
				return nil, err
			}
			candidates = expanded
		}
		if len(candidates) == 0 {
			return nil, nil
		}
	}
	sort.Strings(candidates)
	paths := make([]string, len(candidates))
	for index, candidate := range candidates {
		paths[index] = filepath.FromSlash(candidate)
	}
	return paths, nil
}

// splitTemplateGlobRoot splits a pattern into its longest literal directory
// prefix and the remaining segments, so recursion starts at the closest
// relevant directory instead of scanning unrelated parts of the tree.
func splitTemplateGlobRoot(pattern string) (string, []string) {
	volume := filepath.VolumeName(pattern)
	rest := filepath.ToSlash(pattern[len(volume):])
	leading := strings.HasPrefix(rest, "/")
	segments := strings.Split(strings.Trim(rest, "/"), "/")
	literal := 0
	for literal < len(segments) && !strings.ContainsAny(segments[literal], "*?[") {
		literal++
	}
	root := volume
	if leading {
		root += "/"
	}
	root += strings.Join(segments[:literal], "/")
	if root == "" {
		root = "."
	}
	return root, segments[literal:]
}

// expandTemplateRecursiveSegment replaces every candidate with itself and all
// of its descendants, which is what a ** segment matches. Symbolic links are
// never followed, matching filepath.WalkDir, so a link loop cannot hang the
// template.
func expandTemplateRecursiveSegment(candidates []string) []string {
	var expanded []string
	for _, candidate := range candidates {
		osPath := filepath.FromSlash(candidate)
		info, err := os.Stat(osPath)
		if err != nil {
			continue
		}
		expanded = append(expanded, candidate)
		if !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(osPath, func(path string, _ fs.DirEntry, err error) error {
			if err != nil || path == osPath {
				return nil
			}
			expanded = append(expanded, filepath.ToSlash(path))
			return nil
		})
	}
	return expanded
}

// expandTemplateMetaSegment expands one shell-style segment below every
// candidate with filepath.Glob, keeping the behaviour of *, ? and character
// classes unchanged from plain shell globs.
func expandTemplateMetaSegment(candidates []string, segment string) ([]string, error) {
	var expanded []string
	for _, candidate := range candidates {
		matches, err := filepath.Glob(filepath.FromSlash(strings.TrimSuffix(candidate, "/") + "/" + segment))
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			expanded = append(expanded, filepath.ToSlash(match))
		}
	}
	return expanded, nil
}

// readTemplateFile reads one file bounded by the template output limit so a
// large include fails instead of exhausting memory.
func readTemplateFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cat %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxTemplateOutput+1))
	if err != nil {
		return "", fmt.Errorf("cat %q: %w", path, err)
	}
	if len(data) > maxTemplateOutput {
		return "", fmt.Errorf("cat %q exceeds 8 MiB", path)
	}
	return string(data), nil
}

// templateFromJSON decodes JSON text into a template value so conditions can
// inspect structured data, for example a JSON status file kept next to the
// configuration. The decoder implements the JSON5 superset, so JSONC comments
// and trailing commas as well as JSON5 unquoted keys, single quoted strings
// and hexadecimal numbers are accepted. Unlike the Sprig helper it reports
// malformed input instead of silently producing nil, which would fail later
// with an unrelated error.
func templateFromJSON(value string) (interface{}, error) {
	if err := checkTemplateJSON5Balance(value); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	output, err := json5.Unmarshal(value)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return output, nil
}

// checkTemplateJSON5Balance rejects input whose brackets never close. The
// JSON5 parser accepts a truncated object such as "{" or "{\"a\":1," as an
// empty object, which would silently drop every field of a partially written
// file, so the delimiters are matched again on the token stream. Comments are
// ignored and braces inside strings never become tokens.
func checkTemplateJSON5Balance(value string) error {
	var stack []json5.TokenType
	for _, token := range json5.Tokenize(value) {
		switch token.Type {
		case json5.TOKEN_LBRACE, json5.TOKEN_LBRACKET:
			stack = append(stack, token.Type)
		case json5.TOKEN_RBRACE, json5.TOKEN_RBRACKET:
			expected := json5.TOKEN_LBRACE
			if token.Type == json5.TOKEN_RBRACKET {
				expected = json5.TOKEN_LBRACKET
			}
			if len(stack) == 0 || stack[len(stack)-1] != expected {
				return fmt.Errorf("unexpected %q", token.Value)
			}
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("unexpected end of input")
	}
	return nil
}

// templateFromYAML decodes YAML text with the same library the mihomo
// configuration itself uses, so mappings arrive as maps and can be read with
// template field access.
func templateFromYAML(value string) (interface{}, error) {
	var output interface{}
	if err := yaml.Unmarshal([]byte(value), &output); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	return output, nil
}

// templateFromTOML decodes TOML text, which is how rule sets and other
// auxiliary files ship comments that JSON cannot carry.
func templateFromTOML(value string) (interface{}, error) {
	var output interface{}
	if err := toml.Unmarshal([]byte(value), &output); err != nil {
		return nil, fmt.Errorf("invalid TOML: %w", err)
	}
	return output, nil
}

func runTemplateCommand(command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), templateCommandTimeout)
	defer cancel()
	var cmd *exec.Cmd
	var err error
	commandName := command
	if containsTemplatePipeline(command) {
		cmd = shellTemplateCommand(ctx, command)
		commandName = shellCommandName()
	} else {
		args, err := splitTemplateCommandArgs(command)
		if err != nil {
			return "", err
		}
		if len(args) == 0 {
			return "", fmt.Errorf("command is empty")
		}
		values := make([]string, len(args))
		for index, arg := range args {
			if arg.expandable {
				arg.value = expandTemplateCommandEnv(arg.value)
			}
			values[index] = arg.value
		}
		cmd = exec.CommandContext(ctx, values[0], values[1:]...)
		commandName = values[0]
	}
	cmd.Env = templateCommandEnv()

	var stdout, stderr limitedCommandOutput
	stdout.limit = maxTemplateOutput
	stderr.limit = maxTemplateCommandError
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if stdout.exceeded {
		return "", fmt.Errorf("command %q output exceeds 8 MiB", commandName)
	}
	if stderr.exceeded {
		return "", fmt.Errorf("command %q stderr exceeds 64 KiB", commandName)
	}
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("command %q timed out after %s", commandName, templateCommandTimeout)
		}
		if stderr.buf.Len() > 0 {
			return "", fmt.Errorf("command %q failed: %w: %s", commandName, err, strings.TrimSpace(stderr.buf.String()))
		}
		return "", fmt.Errorf("command %q failed: %w", commandName, err)
	}
	return stdout.buf.String(), nil
}

func shellCommandName() string {
	if runtime.GOOS == "windows" {
		return "cmd.exe"
	}
	return "/bin/sh"
}

func templateCommandEnv() []string {
	configFile := C.Path.Config()
	return append(os.Environ(),
		"MIHOMO_VERSION="+C.Version,
		"MIHOMO_CFG_DIR="+filepath.Dir(configFile),
		"MIHOMO_CFG_FILE="+configFile,
	)
}

func containsTemplatePipeline(command string) bool {
	var quote rune
	escaped := false
	for _, char := range command {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '\'' || char == '"' {
			quote = char
			continue
		}
		if char == '|' {
			return true
		}
	}
	return false
}

// templateCommandArg is a single argument produced by the splitter. expandable
// records whether the argument contains any text that was not wrapped in
// single quotes, mirroring shell semantics where only unquoted and
// double-quoted $VAR references are expanded.
type templateCommandArg struct {
	value      string
	expandable bool
}

func splitTemplateCommand(command string) ([]string, error) {
	args, err := splitTemplateCommandArgs(command)
	if err != nil {
		return nil, err
	}
	values := make([]string, len(args))
	for index, arg := range args {
		values[index] = arg.value
	}
	return values, nil
}

func splitTemplateCommandArgs(command string) ([]templateCommandArg, error) {
	var args []templateCommandArg
	var current strings.Builder
	var quote rune
	escaped := false
	hasValue := false
	expandable := false

	flush := func() {
		if hasValue {
			args = append(args, templateCommandArg{value: current.String(), expandable: expandable})
			current.Reset()
			hasValue = false
			expandable = false
		}
	}

	chars := []rune(command)
	for index := 0; index < len(chars); index++ {
		char := chars[index]
		if escaped {
			current.WriteRune(char)
			hasValue = true
			expandable = true
			escaped = false
			continue
		}
		if char == '\\' && quote != '\'' {
			if index+1 < len(chars) && (chars[index+1] == '\\' || chars[index+1] == '"' || chars[index+1] == ' ' || chars[index+1] == '\t' || chars[index+1] == '\n' || chars[index+1] == '\r') {
				escaped = true
				hasValue = true
				expandable = true
				continue
			}
			current.WriteRune(char)
			hasValue = true
			expandable = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				current.WriteRune(char)
				hasValue = true
				// Double quotes still allow variable expansion; single quotes
				// make the contents fully literal.
				if quote != '\'' {
					expandable = true
				}
			}
			continue
		}
		switch char {
		case '\'', '"':
			quote = char
			hasValue = true
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			current.WriteRune(char)
			hasValue = true
			expandable = true
		}
	}

	if escaped {
		return nil, fmt.Errorf("command has a trailing escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("command has an unterminated quote")
	}
	flush()
	return args, nil
}

// lookupTemplateCommandEnv resolves an environment variable the same way the
// spawned command sees it, including the runtime variables injected by
// templateCommandEnv.
func lookupTemplateCommandEnv(name string) string {
	if value, ok := templateCommandRuntimeEnv(name); ok {
		return value
	}
	return os.Getenv(name)
}

// expandTemplateCommandEnv expands environment variable references in an
// argument. On the direct exec path no shell is involved, so nothing else
// would perform this substitution; doing it here keeps `cmd` usable for paths
// built from the runtime variables on every platform.
//
// The syntax follows the platform shell: `$VAR`/`${VAR}` on Unix, `%VAR%` on
// Windows.
func expandTemplateCommandEnv(value string) string {
	if runtime.GOOS == "windows" {
		return expandWindowsTemplateCommandEnv(value)
	}
	return os.Expand(value, lookupTemplateCommandEnv)
}

// expandWindowsTemplateCommandEnv replaces %NAME% references, leaving a
// reference untouched when the variable is not set, matching cmd.exe.
func expandWindowsTemplateCommandEnv(value string) string {
	var out strings.Builder
	for index := 0; index < len(value); {
		if value[index] != '%' {
			out.WriteByte(value[index])
			index++
			continue
		}
		end := strings.IndexByte(value[index+1:], '%')
		if end == 0 {
			// "%%" is an escaped percent sign in batch files.
			out.WriteByte('%')
			index += 2
			continue
		}
		if end < 0 {
			out.WriteString(value[index:])
			break
		}
		name := value[index+1 : index+1+end]
		if resolved, ok := os.LookupEnv(name); ok {
			out.WriteString(resolved)
		} else if runtimeValue, ok := templateCommandRuntimeEnv(name); ok {
			out.WriteString(runtimeValue)
		} else {
			out.WriteString(value[index : index+end+2])
		}
		index += end + 2
	}
	return out.String()
}

func templateCommandRuntimeEnv(name string) (string, bool) {
	switch name {
	case "MIHOMO_VERSION":
		return C.Version, true
	case "MIHOMO_CFG_DIR":
		return filepath.Dir(C.Path.Config()), true
	case "MIHOMO_CFG_FILE":
		return C.Path.Config(), true
	}
	return "", false
}

type limitedCommandOutput struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedCommandOutput) Write(p []byte) (int, error) {
	if b.exceeded {
		return 0, fmt.Errorf("command output limit exceeded")
	}
	if b.buf.Len()+len(p) > b.limit {
		allowed := b.limit - b.buf.Len()
		if allowed > 0 {
			_, _ = b.buf.Write(p[:allowed])
		}
		b.exceeded = true
		return allowed, fmt.Errorf("command output limit exceeded")
	}
	return b.buf.Write(p)
}

func renderTemplate(buf []byte) ([]byte, error) {
	tpl, err := template.New("mihomo-config").Option("missingkey=error").Funcs(templateFuncMap()).Parse(string(buf))
	if err != nil {
		return nil, fmt.Errorf("config template parse: %w", err)
	}

	var out limitedBuffer
	if err := tpl.Execute(&out, newTemplateData()); err != nil {
		return nil, fmt.Errorf("config template execute: %w", err)
	}
	if out.exceeded {
		return nil, fmt.Errorf("config template output exceeds 8 MiB")
	}
	return out.buf.Bytes(), nil
}

func RenderTemplateBytes(buf []byte, secretKeys ...string) ([]byte, error) {
	decrypted, err := age.DecryptBytes(buf, secretKeys...)
	if err != nil {
		return nil, fmt.Errorf("config decrypt: %w", err)
	}
	return renderTemplate(decrypted)
}

type limitedBuffer struct {
	buf      bytes.Buffer
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.exceeded {
		return len(p), nil
	}
	if b.buf.Len()+len(p) > maxTemplateOutput {
		allowed := maxTemplateOutput - b.buf.Len()
		if allowed > 0 {
			_, _ = b.buf.Write(p[:allowed])
		}
		b.exceeded = true
		return len(p), nil
	}
	return b.buf.Write(p)
}
