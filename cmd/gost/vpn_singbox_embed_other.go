//go:build !windows

package main

func ensureEmbeddedSingBox() (string, error) {
	return "", nil
}
