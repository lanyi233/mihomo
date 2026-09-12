//go:build !windows

package config

import (
	"context"
	"os/exec"
)

func shellTemplateCommand(ctx context.Context, command string) *exec.Cmd {
	return exec.CommandContext(ctx, "/bin/sh", "-c", command)
}
