//go:build wasip1

package coff

import (
	"fmt"
	"unsafe"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/windef"

	"golang.org/x/sys/windows"
)

func processRelocation(symbolDefAddress uintptr, sectionAddress uintptr, reloc windef.Relocation, symbol *pecoff.Symbol) {
	symbolOffset := (uintptr)(reloc.VirtualAddress)
	absoluteSymbolAddress := symbolOffset + sectionAddress

	// Compute host-space equivalents for relocation value calculations.
	// Shadow memory addresses in WASM don't correspond to the host addresses
	// where code actually executes.
	hostSection := sectionAddress
	if h, err := windows.HostMemoryAddress(sectionAddress); err == nil {
		hostSection = h
	}
	hostAbsolute := symbolOffset + hostSection

	segmentValue := *(*uint32)(unsafe.Pointer(absoluteSymbolAddress))

	if (symbol.StorageClass == windef.IMAGE_SYM_CLASS_STATIC && symbol.Value != 0) ||
		(symbol.StorageClass == windef.IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber != 0) {
		symbolOffset = (uintptr)(symbol.Value)
	} else {
		symbolDefAddress += (uintptr)(segmentValue)
	}

	hostSymDef := symbolDefAddress
	if h, err := windows.HostMemoryAddress(symbolDefAddress); err == nil {
		hostSymDef = h
	}

	switch reloc.Type {
	case windef.IMAGE_REL_AMD64_ADDR64:
		addr := (*uint64)(unsafe.Pointer(absoluteSymbolAddress))
		fmt.Sprintf("Symbol Ref Address: 0x%x\n", addr)
		*addr = uint64(hostSymDef)
	case windef.IMAGE_REL_AMD64_ADDR32NB:
		addr := (*uint32)(unsafe.Pointer(absoluteSymbolAddress))
		valueToWrite := hostSymDef - (hostSection + 4 + symbolOffset)
		fmt.Sprintf("Symbol Ref Address: 0x%x\n", addr)
		*addr = uint32(valueToWrite)
	case windef.IMAGE_REL_AMD64_REL32, windef.IMAGE_REL_AMD64_REL32_1,
		windef.IMAGE_REL_AMD64_REL32_2, windef.IMAGE_REL_AMD64_REL32_3,
		windef.IMAGE_REL_AMD64_REL32_4, windef.IMAGE_REL_AMD64_REL32_5:
		relativeSymbolDefAddress := hostSymDef - (uintptr)(reloc.Type-4) - (hostAbsolute + 4)
		addr := (*uint32)(unsafe.Pointer(absoluteSymbolAddress))
		fmt.Sprintf("Symbol Ref Address: 0x%x\n", addr)
		*addr = uint32(relativeSymbolDefAddress)
	default:
		fmt.Printf("Unsupported relocation type: %d\n", reloc.Type)
	}
}
