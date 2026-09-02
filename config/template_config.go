package config

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/metacubex/mihomo/component/age"
	C "github.com/metacubex/mihomo/constant"
)

const maxTemplateOutput = 8 << 20

type TemplateData struct {
	System SystemTemplateData
}

type SystemTemplateData struct {
	OS      string
	Arch    string
	Version string
}

func newTemplateData() TemplateData {
	return TemplateData{System: SystemTemplateData{
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Version: C.Version,
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
	return funcs
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
