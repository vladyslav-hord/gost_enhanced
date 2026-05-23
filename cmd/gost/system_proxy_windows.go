//go:build windows

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var (
	wininet                       = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW        = wininet.NewProc("InternetSetOptionW")
	internetOptionRefresh         = uintptr(37)
	internetOptionSettingsChanged = uintptr(39)
)

func enableSystemProxy(target systemProxyTarget) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := key.SetStringValue("ProxyServer", target.WindowsProxyServer()); err != nil {
		return err
	}

	notifySystemProxyChanged()
	return nil
}

func disableSystemProxy() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
		return err
	}

	notifySystemProxyChanged()
	return nil
}

func notifySystemProxyChanged() {
	procInternetSetOptionW.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOptionW.Call(0, internetOptionRefresh, uintptr(unsafe.Pointer(nil)), 0)
}
