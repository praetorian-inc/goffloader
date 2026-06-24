//go:build !wasip1

package coff

func resolveHostAddr(addr uintptr) uintptr { return addr }
