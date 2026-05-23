//go:build !windows

package main

import "errors"

func enableSystemProxy(target systemProxyTarget) error {
	return errors.New("system proxy toggle is only implemented on Windows")
}

func disableSystemProxy() error {
	return errors.New("system proxy toggle is only implemented on Windows")
}
