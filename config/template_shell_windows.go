//go:build windows

package config

import (
	"context"
	"os/exec"
	"syscall"
)

// cmd.exe uses a command-line unquoting algorithm that is incompatible with
// the CommandLineToArgvW-style escaping that exec.Cmd applies to Args, so the
// command line is built manually. /d disables registry AutoRun, /s makes
// cmd.exe strip only the outermost quotes that protect pipes and
// redirections, /c runs the command and exits.
func shellTemplateCommand(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, shellCommandName())
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: shellCommandName() + ` /d /s /c "` + command + `"`,
	}
	return cmd
}
