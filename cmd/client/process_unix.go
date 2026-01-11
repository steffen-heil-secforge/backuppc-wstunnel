//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func initProcessGroup() error {
	return nil
}

func assignToProcessGroup(cmd *exec.Cmd) error {
	// On Unix, set process group in SysProcAttr before starting
	return nil
}

func setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killProcessGroup() {
	// Handled in killRsync via process kill
}
