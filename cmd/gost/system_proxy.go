package main

import "fmt"

type systemProxyTarget struct {
	Mode string
	Addr string
}

func (target systemProxyTarget) Display() string {
	return "HTTP/HTTPS " + target.Addr
}

func (target systemProxyTarget) WindowsProxyServer() string {
	return fmt.Sprintf("http=%s;https=%s", target.Addr, target.Addr)
}
