//go:build !unix

package facts

import "os/exec"

func setProcessGroup(*exec.Cmd) {}
