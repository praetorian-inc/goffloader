//go:build !wasip1

package coff

func freeShadowAllocations(sections map[string]CoffSection, gotBaseAddress uintptr) {
	// No-op on native Windows. OS reclaims memory on process exit.
}
