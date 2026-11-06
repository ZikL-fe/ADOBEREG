//go:build !windows

package activate

import "os/exec"

func hideCmd(cmd *exec.Cmd) {}
