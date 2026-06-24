//go:build windows

package coff

func resolveHostAddr(addr uintptr) uintptr { return addr }
