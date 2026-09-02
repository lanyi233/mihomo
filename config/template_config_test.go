package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/age"
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
	buf, err := renderTemplate([]byte(`{{ .System.OS }} {{ .System.Arch }} {{ .System.Version }}`))
	require.NoError(t, err)
	require.Contains(t, string(buf), runtime.GOOS)
	require.Contains(t, string(buf), runtime.GOARCH)
	require.NotEmpty(t, os.Getenv("PATH"))
}
