//go:build unix

package facts

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcessGroup starts cmd in its own process group and makes cancellation kill the group.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		// Negative pid: the whole group (pgid == pid after Setpgid).
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
