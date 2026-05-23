//go:build windows

package main

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

//go:embed assets/sing-box-windows-amd64.exe
var embeddedSingBoxWindowsAMD64 []byte

func ensureEmbeddedSingBox() (string, error) {
	if runtime.GOARCH != "amd64" {
		return "", fmt.Errorf("embedded sing-box is not available for windows/%s", runtime.GOARCH)
	}
	if len(embeddedSingBoxWindowsAMD64) == 0 {
		return "", errors.New("embedded sing-box asset is empty")
	}

	storePath, err := profileStorePath()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(filepath.Dir(storePath), "bin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}

	hash := sha256Hex(embeddedSingBoxWindowsAMD64)
	path := filepath.Join(dir, "sing-box-"+hash[:12]+".exe")
	if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Size() == int64(len(embeddedSingBoxWindowsAMD64)) {
		return path, nil
	}
	_ = os.Remove(path)

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, embeddedSingBoxWindowsAMD64, 0o700); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return path, nil
}
