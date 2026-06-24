//go:build wasip1

package coff

import "golang.org/x/sys/windows"

func resolveHostAddr(addr uintptr) uintptr {
	if h, err := windows.HostMemoryAddress(addr); err == nil {
		return h
	}
	return addr
}
