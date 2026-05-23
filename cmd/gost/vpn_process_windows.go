//go:build windows

package main

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func currentProcessCanStartVPN() bool {
	shell32 := syscall.NewLazyDLL("shell32.dll")
	isUserAnAdmin := shell32.NewProc("IsUserAnAdmin")
	ret, _, _ := isUserAnAdmin.Call()
	return ret != 0
}

func processExists(pid int) bool {
	return processMatches(pid, "")
}

func processMatches(pid int, executable string) bool {
	if pid <= 0 {
		return false
	}
	args := []string{"Win32_Process", "where", "ProcessId=" + strconv.Itoa(pid), "get", "ExecutablePath", "/value"}
	out, err := exec.Command("wmic", args...).Output()
	if err != nil {
		out, err = exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/FO", "CSV", "/NH").Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), strconv.Itoa(pid))
	}
	output := string(out)
	if !strings.Contains(output, "ExecutablePath=") {
		return false
	}
	if executable == "" {
		return true
	}
	actual, ok := parseWMICExecutablePath(output)
	if !ok {
		return false
	}
	actual = filepath.Clean(actual)
	expected := filepath.Clean(executable)
	return strings.EqualFold(actual, expected)
}

func vpnBackendProcessInfo(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	out, err := exec.Command("wmic", "Win32_Process", "where", "ProcessId="+strconv.Itoa(pid), "get", "ExecutablePath", "/value").Output()
	if err != nil {
		return "", false
	}
	output := strings.TrimSpace(string(out))
	if !strings.Contains(output, "ExecutablePath=") {
		return "", false
	}
	return parseWMICExecutablePath(output)
}

func parseWMICExecutablePath(output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ExecutablePath=") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "ExecutablePath="))
			return value, value != ""
		}
	}
	return "", false
}
