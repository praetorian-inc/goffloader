//go:build !wasip1

package coff

import (
	"fmt"
	"unsafe"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/windef"
)

func processRelocation(symbolDefAddress uintptr, sectionAddress uintptr, reloc windef.Relocation, symbol *pecoff.Symbol) {
	symbolOffset := (uintptr)(reloc.VirtualAddress)
	absoluteSymbolAddress := symbolOffset + sectionAddress
	segmentValue := *(*uint32)(unsafe.Pointer(absoluteSymbolAddress))

	if (symbol.StorageClass == windef.IMAGE_SYM_CLASS_STATIC && symbol.Value != 0) ||
		(symbol.StorageClass == windef.IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber != 0) {
		symbolOffset = (uintptr)(symbol.Value)
	} else {
		symbolDefAddress += (uintptr)(segmentValue)
	}

	symbolRefAddress := sectionAddress

	switch reloc.Type {
	case windef.IMAGE_REL_AMD64_ADDR64:
		addr := (*uint64)(unsafe.Pointer(absoluteSymbolAddress))
		fmt.Sprintf("Symbol Ref Address: 0x%x\n", addr)
		*addr = uint64(symbolDefAddress)
	case windef.IMAGE_REL_AMD64_ADDR32NB:
		addr := (*uint32)(unsafe.Pointer(absoluteSymbolAddress))
		valueToWrite := symbolDefAddress - (symbolRefAddress + 4 + symbolOffset)
		fmt.Sprintf("Symbol Ref Address: 0x%x\n", addr)
		*addr = uint32(valueToWrite)
	case windef.IMAGE_REL_AMD64_REL32, windef.IMAGE_REL_AMD64_REL32_1,
		windef.IMAGE_REL_AMD64_REL32_2, windef.IMAGE_REL_AMD64_REL32_3,
		windef.IMAGE_REL_AMD64_REL32_4, windef.IMAGE_REL_AMD64_REL32_5:
		relativeSymbolDefAddress := symbolDefAddress - (uintptr)(reloc.Type-4) - (absoluteSymbolAddress + 4)
		addr := (*uint32)(unsafe.Pointer(absoluteSymbolAddress))
		fmt.Sprintf("Symbol Ref Address: 0x%x\n", addr)
		*addr = uint32(relativeSymbolDefAddress)
	default:
		fmt.Printf("Unsupported relocation type: %d\n", reloc.Type)
	}
}
