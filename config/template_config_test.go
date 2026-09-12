package config

import (
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

func TestSplitTemplateCommand(t *testing.T) {
	args, err := splitTemplateCommand(`'path/to/program' "argument with spaces" 1 2`)
	require.NoError(t, err)
	require.Equal(t, []string{"path/to/program", "argument with spaces", "1", "2"}, args)

	_, err = splitTemplateCommand(`'unterminated`)
	require.Error(t, err)
}

func TestRunTemplateCommand(t *testing.T) {
	output, err := runTemplateCommand(`printf 'hello %s' world`)
	require.NoError(t, err)
	require.Equal(t, "hello world", output)

	_, err = runTemplateCommand("command-that-does-not-exist")
	require.Error(t, err)
}

func TestRunTemplateCommandPipeline(t *testing.T) {
	output, err := runTemplateCommand(`(printf 'hello') | (tr 'a-z' 'A-Z')`)
	require.NoError(t, err)
	require.Equal(t, "HELLO", output)
}

func TestRunTemplateCommandWithQuotedPathAndArguments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "program with spaces")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s|%s|%s' \"$1\" \"$2\" \"$3\"\n"), 0o700))
	output, err := runTemplateCommand(fmt.Sprintf("%q 1 2 3", path))
	require.NoError(t, err)
	require.Equal(t, "1|2|3", output)
}

func TestRunTemplateCommandRuntimeEnv(t *testing.T) {
	// shell pipeline branch
	output, err := runTemplateCommand(`printf '%s' "$MIHOMO_VERSION" | cat`)
	require.NoError(t, err)
	require.Equal(t, C.Version, output)

	// direct exec branch
	dir := t.TempDir()
	script := filepath.Join(dir, "env.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s|%s|%s' \"$MIHOMO_VERSION\" \"$MIHOMO_CFG_DIR\" \"$MIHOMO_CFG_FILE\"\n"), 0o700))
	output, err = runTemplateCommand(script)
	require.NoError(t, err)
	configFile := C.Path.Config()
	require.Equal(t, C.Version+"|"+filepath.Dir(configFile)+"|"+configFile, output)
}
