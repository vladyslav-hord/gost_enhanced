//go:build !windows

package main

import (
	"os"
	"syscall"
)

func currentProcessCanStartVPN() bool {
	return os.Geteuid() == 0
}

func processExists(pid int) bool {
	return processMatches(pid, "")
}

func processMatches(pid int, executable string) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if process.Signal(syscall.Signal(0)) != nil {
		return false
	}
	return true
}
