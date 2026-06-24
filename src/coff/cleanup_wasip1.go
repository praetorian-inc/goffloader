//go:build wasip1

package coff

import "golang.org/x/sys/windows"

const memRelease = 0x00008000

func freeShadowAllocations(sections map[string]CoffSection, gotBaseAddress uintptr) {
	for _, sec := range sections {
		if sec.Address != 0 {
			windows.VirtualFree(sec.Address, 0, memRelease)
		}
	}
	if gotBaseAddress != 0 {
		windows.VirtualFree(gotBaseAddress, 0, memRelease)
	}
}
