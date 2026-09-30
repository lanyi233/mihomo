package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/age"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

const templateCommandHelperFlag = "-mihomo-template-cmd-helper"

func runTemplateCommandHelper(mode string, args []string) {
	switch mode {
	case "echo-args":
		fmt.Printf("%s|%s|%s", args[0], args[1], args[2])
	case "echo-env":
		fmt.Printf("%s|%s|%s", os.Getenv("MIHOMO_VERSION"), os.Getenv("MIHOMO_CFG_DIR"), os.Getenv("MIHOMO_CFG_FILE"))
	case "print":
		fmt.Print(args[0])
	default:
		fmt.Fprintf(os.Stderr, "unknown helper mode %q", mode)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == templateCommandHelperFlag {
		runTemplateCommandHelper(os.Args[2], os.Args[3:])
	}
	os.Exit(m.Run())
}

func templateCommandHelperPath(t *testing.T) string {
	exe, err := os.Executable()
	require.NoError(t, err)
	return exe
}

func quoteTemplateCommandArg(path string) string {
	return `"` + path + `"`
}

func TestRenderTemplate(t *testing.T) {
	t.Setenv("MIHOMO_TEMPLATE_VALUE", "one")
	buf, err := renderTemplate([]byte(`{{- $base := "https://example.test" -}}
{{- $items := tuple "a" "b" -}}
rule-providers:
  test:
    type: http
    behavior: domain
    url: {{ printf "%s/%s" $base (env "MIHOMO_TEMPLATE_VALUE") | quote }}
rules:
{{ range $item := $items }}
  - DOMAIN,{{ $item }},DIRECT
{{ end }}
{{ if eq .System.OS "` + runtime.GOOS + `" }}
  - DOMAIN,{{ .System.Arch }},DIRECT
{{ end }}`))
	require.NoError(t, err)
	require.Contains(t, string(buf), "https://example.test/one")
	require.Contains(t, string(buf), runtime.GOARCH)
	require.NotContains(t, string(buf), "{{")
	raw, err := UnmarshalRawConfig(buf)
	require.NoError(t, err)
	require.Len(t, raw.RuleProvider, 1)
	require.Len(t, raw.Rule, 3)
}

func TestRenderTemplateEnvironment(t *testing.T) {
	t.Setenv("MIHOMO_EMPTY", "")
	buf, err := renderTemplate([]byte(`{{ env "MIHOMO_EMPTY" | quote }}`))
	require.NoError(t, err)
	require.Equal(t, `""`, strings.TrimSpace(string(buf)))

	_, err = renderTemplate([]byte(`{{ env "MIHOMO_MISSING" }}`))
	require.ErrorContains(t, err, "config template execute")
	_, err = renderTemplate([]byte(`{{ expandenv "${MIHOMO_MISSING}" }}`))
	require.ErrorContains(t, err, "config template execute")
}

func TestTemplateErrorsAndLimit(t *testing.T) {
	_, err := renderTemplate([]byte(`{{ if }}`))
	require.ErrorContains(t, err, "config template parse")
	_, err = renderTemplate([]byte(`{{ .Missing }}`))
	require.ErrorContains(t, err, "config template execute")

	_, err = renderTemplate([]byte(`{{ repeat 8388609 "x" }}`))
	require.EqualError(t, err, "config template output exceeds 8 MiB")
}

func TestUnmarshalRawConfigTemplateDefault(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("port: {{ 7890 }}\n"))
	require.NoError(t, err)
	require.Equal(t, 7890, raw.Port)
}

func TestParseTemplateDefault(t *testing.T) {
	t.Setenv("MIHOMO_CONFIG_PORT", "7891")
	raw, err := UnmarshalRawConfig([]byte("port: {{ env \"MIHOMO_CONFIG_PORT\" }}\n"))
	require.NoError(t, err)
	require.Equal(t, 7891, raw.Port)
}

func TestUnmarshalRawConfigTemplateAgeOrdering(t *testing.T) {
	secretKey, publicKey, err := age.GenX25519KeyPair()
	require.NoError(t, err)
	input, err := age.EncryptBytes([]byte("port: {{ 7892 }}\n"), publicKey)
	require.NoError(t, err)
	age.SetGlobalSecretKeys(secretKey)
	t.Cleanup(func() { age.SetGlobalSecretKeys() })
	raw, err := UnmarshalRawConfig(input)
	require.NoError(t, err)
	require.Equal(t, 7892, raw.Port)
}

func TestRenderTemplateBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("port: {{ 7893 }}\n"), 0o600))
	buf, err := os.ReadFile(path)
	require.NoError(t, err)
	raw, err := RenderTemplateBytes(buf)
	require.NoError(t, err)
	require.Contains(t, string(raw), "port: 7893")
}

func TestTemplateSystemData(t *testing.T) {
	buf, err := renderTemplate([]byte(`{{ .System.OS }} {{ .System.Arch }}`))
	require.NoError(t, err)
	require.Contains(t, string(buf), runtime.GOOS)
	require.Contains(t, string(buf), runtime.GOARCH)
	require.NotEmpty(t, os.Getenv("PATH"))
}

func setTemplateConfigFile(t *testing.T, path string) {
	previous := C.Path.Config()
	C.SetConfig(path)
	t.Cleanup(func() { C.SetConfig(previous) })
}

func TestRenderTemplateCat(t *testing.T) {
	dir := t.TempDir()
	subconfig := filepath.Join(dir, "subconfig")
	require.NoError(t, os.Mkdir(subconfig, 0o755))
	// Sorted glob order, and the first file has no trailing newline so the
	// include must add the separator itself.
	require.NoError(t, os.WriteFile(filepath.Join(subconfig, "a.yaml"), []byte("port-a: 1"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(subconfig, "empty.yaml"), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(subconfig, "b.yaml"), []byte("port-b: 2\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "single.yaml"), []byte("port-s: 3\n"), 0o600))
	setTemplateConfigFile(t, filepath.Join(dir, "config.yaml"))

	buf, err := renderTemplate([]byte(`{{ cat "subconfig/*.yaml" }}`))
	require.NoError(t, err)
	require.Equal(t, "port-a: 1\nport-b: 2\n", string(buf))

	buf, err = renderTemplate([]byte(`{{ cat "subconfig/a.yaml" "subconfig/empty.yaml" "subconfig/b.yaml" }}`))
	require.NoError(t, err)
	require.Equal(t, "port-a: 1\nport-b: 2\n", string(buf))

	buf, err = renderTemplate([]byte(`{{ cat "single.yaml" }}`))
	require.NoError(t, err)
	require.Equal(t, "port-s: 3\n", string(buf))

	buf, err = renderTemplate([]byte(`{{ cat "subconfig/a.yaml" "subconfig/b.yaml" }}`))
	require.NoError(t, err)
	require.Equal(t, "port-a: 1\nport-b: 2\n", string(buf))

	buf, err = renderTemplate([]byte(fmt.Sprintf(`{{ cat %q }}`, filepath.Join(dir, "single.yaml"))))
	require.NoError(t, err)
	require.Equal(t, "port-s: 3\n", string(buf))
}

func TestRenderTemplateCatRecursive(t *testing.T) {
	dir := t.TempDir()
	subconfig := filepath.Join(dir, "subconfig")
	require.NoError(t, os.MkdirAll(filepath.Join(subconfig, "nested"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(subconfig, "10-root.yaml"), []byte("root: a\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(subconfig, "nested", "deep.yaml"), []byte("deep: b\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(subconfig, ".hidden.yaml"), []byte("hidden: c\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "top.yaml"), []byte("top: d\n"), 0o600))
	setTemplateConfigFile(t, filepath.Join(dir, "config.yaml"))

	// A ** segment matches the directory itself and every level below it,
	// and matched directories are skipped instead of failing the read.
	buf, err := renderTemplate([]byte(`{{ cat "subconfig/**" }}`))
	require.NoError(t, err)
	require.Equal(t, "hidden: c\nroot: a\ndeep: b\n", string(buf))

	// Other segments keep shell behaviour: * stays inside one directory.
	buf, err = renderTemplate([]byte(`{{ cat "subconfig/*" }}`))
	require.NoError(t, err)
	require.Equal(t, "hidden: c\nroot: a\n", string(buf))

	// A ** segment in the middle matches any number of directory levels.
	buf, err = renderTemplate([]byte(`{{ cat "subconfig/**/deep.yaml" }}`))
	require.NoError(t, err)
	require.Equal(t, "deep: b\n", string(buf))

	// The pattern may also start with ** from the configuration directory.
	buf, err = renderTemplate([]byte(`{{ cat "**/top.yaml" }}`))
	require.NoError(t, err)
	require.Equal(t, "top: d\n", string(buf))

	// A literal directory is reported instead of being read.
	_, err = renderTemplate([]byte(`{{ cat "subconfig/nested" }}`))
	require.ErrorContains(t, err, "is a directory")
	_, err = renderTemplate([]byte(`{{ cat "subconfig/**/*.json" }}`))
	require.ErrorContains(t, err, `cat: no file matched "subconfig/**/*.json"`)
}

func TestRenderTemplateCatJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tpl.json"), []byte(`{"success":"true","value":7}`), 0o600))
	setTemplateConfigFile(t, filepath.Join(dir, "config.yaml"))

	buf, err := renderTemplate([]byte(`{{ $anytest := fromJson (cat "tpl.json") }}
{{ if eq $anytest.success "true" }}
cfg: hello world
{{ end }}`))
	require.NoError(t, err)
	require.Contains(t, string(buf), "cfg: hello world")

	buf, err = renderTemplate([]byte(`{{ $anytest := fromJson (cat "tpl.json") }}{{ $anytest.value }}`))
	require.NoError(t, err)
	require.Equal(t, "7", string(buf))

	buf, err = renderTemplate([]byte(`{{ $anytest := fromJson (cat "tpl.json") }}{{ if eq $anytest.success "false" }}cfg: hello world{{ end }}`))
	require.NoError(t, err)
	require.NotContains(t, string(buf), "cfg: hello world")
}

func TestRenderTemplateCatErrors(t *testing.T) {
	dir := t.TempDir()
	setTemplateConfigFile(t, filepath.Join(dir, "config.yaml"))

	_, err := renderTemplate([]byte(`{{ cat "missing.yaml" }}`))
	require.ErrorContains(t, err, `cat: file "missing.yaml" not found`)
	_, err = renderTemplate([]byte(`{{ cat "subconfig/*.yaml" }}`))
	require.ErrorContains(t, err, `cat: no file matched "subconfig/*.yaml"`)
	_, err = renderTemplate([]byte(`{{ cat "" }}`))
	require.ErrorContains(t, err, "cat file path is empty")
	_, err = renderTemplate([]byte(`{{ cat }}`))
	require.ErrorContains(t, err, "cat requires at least one file path")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "tpl.json"), []byte(`{"success":`), 0o600))
	_, err = renderTemplate([]byte(`{{ fromJson (cat "tpl.json") }}`))
	require.ErrorContains(t, err, "invalid JSON")
}

func TestRenderTemplateCatLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.yaml")
	file, err := os.Create(path)
	require.NoError(t, err)
	_, err = file.Write(bytes.Repeat([]byte("x"), maxTemplateOutput+1))
	require.NoError(t, err)
	require.NoError(t, file.Close())
	setTemplateConfigFile(t, filepath.Join(dir, "config.yaml"))

	_, err = renderTemplate([]byte(`{{ cat "large.yaml" }}`))
	require.ErrorContains(t, err, "exceeds 8 MiB")
}

func TestRenderTemplateFromJSON(t *testing.T) {
	// Strict JSON.
	buf, err := renderTemplate([]byte(`{{ $anytest := fromJson "{\"success\":\"true\",\"port\":7890}" }}{{ if eq $anytest.success "true" }}cfg: hello world{{ end }}`))
	require.NoError(t, err)
	require.Equal(t, "cfg: hello world", string(buf))

	buf, err = renderTemplate([]byte(`{{ $cfg := fromJson "{\"port\":7890}" }}{{ $cfg.port }}`))
	require.NoError(t, err)
	require.Equal(t, "7890", string(buf))

	// JSONC: line and block comments, trailing commas.
	buf, err = renderTemplate([]byte(`{{ $cfg := fromJson "{ /* status */ \"port\": 7890, // the port\n }" }}{{ $cfg.port }}`))
	require.NoError(t, err)
	require.Equal(t, "7890", string(buf))

	// JSON5: unquoted keys, single quoted strings, hexadecimal numbers.
	buf, err = renderTemplate([]byte(`{{ $cfg := fromJson "{ success: 'true', mask: 0xff, }" }}{{ if eq $cfg.success "true" }}cfg: {{ $cfg.mask }}{{ end }}`))
	require.NoError(t, err)
	require.Equal(t, "cfg: 255", string(buf))

	// Malformed input stops rendering with an explicit error.
	_, err = renderTemplate([]byte(`{{ fromJson "{" }}`))
	require.ErrorContains(t, err, "invalid JSON")
	_, err = renderTemplate([]byte(`{{ fromJson "{\"a\": 1," }}`))
	require.ErrorContains(t, err, "invalid JSON")
	_, err = renderTemplate([]byte(`{{ fromJson "}" }}`))
	require.ErrorContains(t, err, "invalid JSON")
	_, err = renderTemplate([]byte(`{{ fromJson "" }}`))
	require.ErrorContains(t, err, "invalid JSON")
}

func TestRenderTemplateFromYAML(t *testing.T) {
	buf, err := renderTemplate([]byte(`{{ $cfg := fromYaml "success: \"true\"\nport: 7890\nnames:\n  - a\n  - b\n" }}{{ if eq $cfg.success "true" }}cfg: {{ $cfg.port }} {{ len $cfg.names }}{{ end }}`))
	require.NoError(t, err)
	require.Equal(t, "cfg: 7890 2", string(buf))

	buf, err = renderTemplate([]byte(`{{ $cfg := fromYaml "enabled: true\n" }}{{ $cfg.enabled }}`))
	require.NoError(t, err)
	require.Equal(t, "true", string(buf))

	_, err = renderTemplate([]byte(`{{ fromYaml "items: [1, 2" }}`))
	require.ErrorContains(t, err, "invalid YAML")
}

func TestRenderTemplateFromTOML(t *testing.T) {
	buf, err := renderTemplate([]byte(`{{ $cfg := fromToml "success = \"true\"\n\n[extra]\nport = 7890\n" }}{{ if eq $cfg.success "true" }}cfg: {{ $cfg.extra.port }}{{ end }}`))
	require.NoError(t, err)
	require.Equal(t, "cfg: 7890", string(buf))

	buf, err = renderTemplate([]byte(`{{ $cfg := fromToml "names = [\"a\", \"b\"]\n" }}{{ len $cfg.names }}`))
	require.NoError(t, err)
	require.Equal(t, "2", string(buf))

	_, err = renderTemplate([]byte(`{{ fromToml "missing assignment" }}`))
	require.ErrorContains(t, err, "invalid TOML")
}

func TestSplitTemplateCommand(t *testing.T) {
	args, err := splitTemplateCommand(`'path/to/program' "argument with spaces" 1 2`)
	require.NoError(t, err)
	require.Equal(t, []string{"path/to/program", "argument with spaces", "1", "2"}, args)

	_, err = splitTemplateCommand(`'unterminated`)
	require.Error(t, err)
}

func TestRunTemplateCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		output, err := runTemplateCommand(`cmd.exe /d /s /c "echo hello world"`)
		require.NoError(t, err)
		require.Equal(t, "hello world", strings.TrimSpace(output))
	} else {
		output, err := runTemplateCommand(`printf 'hello %s' world`)
		require.NoError(t, err)
		require.Equal(t, "hello world", output)
	}

	_, err := runTemplateCommand("command-that-does-not-exist")
	require.Error(t, err)
}

func TestRunTemplateCommandPipeline(t *testing.T) {
	helper := templateCommandHelperPath(t)
	if runtime.GOOS == "windows" {
		output, err := runTemplateCommand(fmt.Sprintf(`%s %s print hello | findstr hello`, quoteTemplateCommandArg(helper), templateCommandHelperFlag))
		require.NoError(t, err)
		require.Equal(t, "hello", strings.TrimSpace(output))
	} else {
		output, err := runTemplateCommand(fmt.Sprintf(`%s %s print hello | cat`, quoteTemplateCommandArg(helper), templateCommandHelperFlag))
		require.NoError(t, err)
		require.Equal(t, "hello", output)
	}
}

func TestRunTemplateCommandWithQuotedPathAndArguments(t *testing.T) {
	source := templateCommandHelperPath(t)
	data, err := os.ReadFile(source)
	require.NoError(t, err)
	name := "program with spaces"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o700))

	output, err := runTemplateCommand(fmt.Sprintf(`%s %s echo-args 1 2 3`, quoteTemplateCommandArg(path), templateCommandHelperFlag))
	require.NoError(t, err)
	require.Equal(t, "1|2|3", strings.TrimSpace(output))
}

func TestRunTemplateCommandRuntimeEnv(t *testing.T) {
	helper := quoteTemplateCommandArg(templateCommandHelperPath(t))
	configFile := C.Path.Config()
	expected := C.Version + "|" + filepath.Dir(configFile) + "|" + configFile

	if runtime.GOOS == "windows" {
		output, err := runTemplateCommand(fmt.Sprintf(`%s %s print %%MIHOMO_VERSION%% | findstr .`, helper, templateCommandHelperFlag))
		require.NoError(t, err)
		require.Equal(t, C.Version, strings.TrimSpace(output))
	} else {
		output, err := runTemplateCommand(fmt.Sprintf(`%s %s print "$MIHOMO_VERSION" | cat`, helper, templateCommandHelperFlag))
		require.NoError(t, err)
		require.Equal(t, C.Version, output)
	}

	output, err := runTemplateCommand(fmt.Sprintf(`%s %s echo-env`, helper, templateCommandHelperFlag))
	require.NoError(t, err)
	require.Equal(t, expected, strings.TrimSpace(output))
}

func TestRunTemplateCommandEnvExpansion(t *testing.T) {
	helper := quoteTemplateCommandArg(templateCommandHelperPath(t))
	configFile := C.Path.Config()

	// direct exec branch: the runner expands environment variable
	// references itself, following the platform shell syntax.
	if runtime.GOOS == "windows" {
		output, err := runTemplateCommand(fmt.Sprintf(`%s %s print %%MIHOMO_CFG_FILE%%`, helper, templateCommandHelperFlag))
		require.NoError(t, err)
		require.Equal(t, configFile, strings.TrimSpace(output))
	} else {
		output, err := runTemplateCommand(fmt.Sprintf(`%s %s print $MIHOMO_CFG_FILE`, helper, templateCommandHelperFlag))
		require.NoError(t, err)
		require.Equal(t, configFile, output)
	}

	// single quotes keep the reference literal, matching shell semantics.
	output, err := runTemplateCommand(fmt.Sprintf(`%s %s print '$MIHOMO_CFG_FILE'`, helper, templateCommandHelperFlag))
	require.NoError(t, err)
	require.Equal(t, "$MIHOMO_CFG_FILE", strings.TrimSpace(output))
}
