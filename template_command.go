package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/config"
)

func templateMain(args []string) int {
	flags := flag.NewFlagSet("template", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	outputPath := flags.String("o", "", "write rendered configuration to a file, or - for stdout")
	secretKey := flags.String("age-secret-key", "", "age secret key to decrypt the input")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if flags.NArg() != 1 {
		flags.Usage = func() {
			_, _ = fmt.Fprintln(os.Stderr, "usage: mihomo template [-o output] [-age-secret-key key] input")
		}
		flags.Usage()
		return 2
	}
	if *secretKey != "" {
		if err := age.VeritySecretKeys(*secretKey); err != nil {
			fatalTemplateCommand(fmt.Errorf("invalid age secret key: %w", err))
			return 1
		}
	}

	inputPath := flags.Arg(0)
	data, err := readTemplateInput(inputPath)
	if err != nil {
		fatalTemplateCommand(err)
		return 1
	}

	rendered, err := config.RenderTemplateBytes(data, *secretKey)
	if err != nil {
		fatalTemplateCommand(err)
		return 1
	}

	if *outputPath == "" || *outputPath == "-" {
		if _, err := os.Stdout.Write(rendered); err != nil {
			fatalTemplateCommand(err)
			return 1
		}
		return 0
	}

	if inputPath != "-" && sameTemplateFile(inputPath, *outputPath) {
		fatalTemplateCommand(fmt.Errorf("input and output paths must be different"))
		return 2
	}
	if err := os.WriteFile(*outputPath, rendered, 0o600); err != nil {
		fatalTemplateCommand(err)
		return 1
	}
	return 0
}

func readTemplateInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func sameTemplateFile(first, second string) bool {
	firstAbs, firstErr := filepath.Abs(first)
	secondAbs, secondErr := filepath.Abs(second)
	if firstErr != nil || secondErr != nil || filepath.Clean(firstAbs) == filepath.Clean(secondAbs) {
		return firstErr == nil && secondErr == nil
	}
	firstInfo, firstStatErr := os.Stat(firstAbs)
	secondInfo, secondStatErr := os.Stat(secondAbs)
	return firstStatErr == nil && secondStatErr == nil && os.SameFile(firstInfo, secondInfo)
}

func fatalTemplateCommand(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "template: %s\n", err)
}
