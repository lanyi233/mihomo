package config

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/metacubex/mihomo/component/age"
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
	return funcs
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
		args, err := splitTemplateCommand(command)
		if err != nil {
			return "", err
		}
		if len(args) == 0 {
			return "", fmt.Errorf("command is empty")
		}
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
		commandName = args[0]
	}

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

func shellTemplateCommand(ctx context.Context, command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd.exe", "/C", command)
	}
	return exec.CommandContext(ctx, "/bin/sh", "-c", command)
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

func splitTemplateCommand(command string) ([]string, error) {
	var args []string
	var current strings.Builder
	var quote rune
	escaped := false
	hasValue := false

	flush := func() {
		if hasValue {
			args = append(args, current.String())
			current.Reset()
			hasValue = false
		}
	}

	chars := []rune(command)
	for index := 0; index < len(chars); index++ {
		char := chars[index]
		if escaped {
			current.WriteRune(char)
			hasValue = true
			escaped = false
			continue
		}
		if char == '\\' && quote != '\'' {
			if index+1 < len(chars) && (chars[index+1] == '\\' || chars[index+1] == '"' || chars[index+1] == ' ' || chars[index+1] == '\t' || chars[index+1] == '\n' || chars[index+1] == '\r') {
				escaped = true
				hasValue = true
				continue
			}
			current.WriteRune(char)
			hasValue = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				current.WriteRune(char)
				hasValue = true
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
