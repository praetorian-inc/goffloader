package coff

import (
	_ "embed"
	"fmt"
	"runtime/debug"
	"strings"
	"syscall"
	"unsafe"

	"github.com/praetorian-inc/goffloader/src/lighthouse"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/binutil"
	"github.com/RIscRIpt/pecoff/windef"

	"golang.org/x/sys/windows"
)

/*
  NOTE: There are random fmt.Sprintfs sprinkled through the code - these are intentional
        and seem to break static Go malware signatures. LEAVE THEM IN PLACE. If this starts
        getting detected again, add some more fmt.Sprintfs.
*/

const (
	MEM_COMMIT             = windows.MEM_COMMIT
	MEM_RESERVE            = windows.MEM_RESERVE
	MEM_TOP_DOWN           = windows.MEM_TOP_DOWN
	PAGE_EXECUTE_READWRITE = windows.PAGE_EXECUTE_READWRITE
	// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READ = windows.PAGE_EXECUTE_READ
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = windows.PAGE_READWRITE

	// Characteristic Flag that implies a section should be executable
	IMAGE_SCN_MEM_EXECUTE = 0x20000000
)

var (
	kernel32           = syscall.MustLoadDLL("kernel32.dll")
	procVirtualAlloc   = kernel32.MustFindProc("VirtualAlloc")
	procVirtualProtect = kernel32.MustFindProc("VirtualProtect")
)

func resolveExternalAddress(symbolName string, outChannel chan<- interface{}) uintptr {
	if strings.HasPrefix(symbolName, "__imp_") {
		symbolName = symbolName[6:]
		// 32 bit import names are __imp__
		if strings.HasPrefix(symbolName, "_") {
			symbolName = symbolName[1:]
		}

		libName := ""
		procName := ""
		// If we're following Dynamic Function Resolution Naming Conventions
		if len(strings.Split(symbolName, "$")) == 2 {
			libName = strings.Split(symbolName, "$")[0] + ".dll"
			procName = strings.Split(symbolName, "$")[1]
		} else {
			procName = symbolName

			switch procName {
			case "FreeLibrary", "LoadLibraryA", "GetProcAddress", "GetModuleHandleA", "GetModuleFileNameA":
				libName = "kernel32.dll"
			case "MessageBoxA":
				libName = "user32.dll"
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'O', 'u', 't', 'p', 'u', 't'}):
				return windows.NewCallback(lighthouse.GetCoffOutputForChannel(outChannel))
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'D', 'a', 't', 'a', 'P', 'a', 'r', 's', 'e'}):
				return windows.NewCallback(lighthouse.DataParse)
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'D', 'a', 't', 'a', 'I', 'n', 't'}):
				return windows.NewCallback(lighthouse.DataInt)
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'D', 'a', 't', 'a', 'S', 'h', 'o', 'r', 't'}):
				return windows.NewCallback(lighthouse.DataShort)
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'D', 'a', 't', 'a', 'L', 'e', 'n', 'g', 't', 'h'}):
				return windows.NewCallback(lighthouse.DataLength)
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'D', 'a', 't', 'a', 'E', 'x', 't', 'r', 'a', 'c', 't'}):
				return windows.NewCallback(lighthouse.DataExtract)
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'P', 'r', 'i', 'n', 't', 'f'}):
				return windows.NewCallback(lighthouse.GetCoffPrintfForChannel(outChannel))
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'A', 'd', 'd', 'V', 'a', 'l', 'u', 'e'}):
				return windows.NewCallback(lighthouse.AddValue)
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'G', 'e', 't', 'V', 'a', 'l', 'u', 'e'}):
				return windows.NewCallback(lighthouse.GetValue)
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'R', 'e', 'm', 'o', 'v', 'e', 'V', 'a', 'l', 'u', 'e'}):
				return windows.NewCallback(lighthouse.RemoveValue)
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'F', 'o', 'r', 'm', 'a', 't', 'A', 'l', 'l', 'o', 'c'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'F', 'o', 'r', 'm', 'a', 't', 'R', 'e', 's', 'e', 't'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'F', 'o', 'r', 'm', 'a', 't', 'F', 'r', 'e', 'e'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'F', 'o', 'r', 'm', 'a', 't', 'A', 'p', 'p', 'e', 'n', 'd'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'F', 'o', 'r', 'm', 'a', 't', 'P', 'r', 'i', 'n', 't', 'f'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'F', 'o', 'r', 'm', 'a', 't', 'T', 'o', 'S', 't', 'r', 'i', 'n', 'g'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'U', 's', 'e', 'T', 'o', 'k', 'e', 'n'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'R', 'e', 'v', 'e', 'r', 't', 'T', 'o', 'k', 'e', 'n'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'I', 's', 'A', 'd', 'm', 'i', 'n'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'G', 'e', 't', 'S', 'p', 'a', 'w', 'n', 'T', 'o'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'S', 'p', 'a', 'w', 'n', 'T', 'e', 'm', 'p', 'o', 'r', 'a', 'r', 'y', 'P', 'r', 'o', 'c', 'e', 's', 's'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'I', 'n', 'j', 'e', 'c', 't', 'P', 'r', 'o', 'c', 'e', 's', 's'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'I', 'n', 'j', 'e', 'c', 't', 'T', 'e', 'm', 'p', 'o', 'r', 'a', 'r', 'y', 'P', 'r', 'o', 'c', 'e', 's', 's'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'C', 'l', 'e', 'a', 'n', 'u', 'p', 'P', 'r', 'o', 'c', 'e', 's', 's'}):
				fallthrough
			case string([]rune{'t', 'o', 'W', 'i', 'd', 'e', 'C', 'h', 'a', 'r'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'G', 'e', 't', 'O', 'u', 't', 'p', 'u', 't', 'D', 'a', 't', 'a'}):
				fallthrough
			case string([]rune{'B', 'e', 'a', 'c', 'o', 'n', 'F', 'o', 'r', 'm', 'a', 't', 'I', 'n', 't'}):
				fallthrough
			default:
				// TODO: Check directives here for libraries
				fmt.Printf("Unknown symbol: %s\n", procName)
				return 0
			}
		}

		libStringPtr, _ := syscall.LoadLibrary(libName)
		procAddress, _ := syscall.GetProcAddress(libStringPtr, procName)
		return procAddress
	}
	return 0
}

func virtualAlloc(lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	ret, _, err := procVirtualAlloc.Call(
		lpAddress,
		dwSize,
		uintptr(flAllocationType),
		uintptr(flProtect),
	)
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func isSpecialSymbol(sym *pecoff.Symbol) bool {
	return sym.StorageClass == windef.IMAGE_SYM_CLASS_EXTERNAL && sym.SectionNumber == 0
}

func isImportSymbol(sym *pecoff.Symbol) bool {
	return strings.HasPrefix(sym.NameString(), "__imp_")
}

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

	//TODO: Handle x86 cases as well
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
	case windef.IMAGE_REL_AMD64_REL32, windef.IMAGE_REL_AMD64_REL32_1, windef.IMAGE_REL_AMD64_REL32_2, windef.IMAGE_REL_AMD64_REL32_3, windef.IMAGE_REL_AMD64_REL32_4, windef.IMAGE_REL_AMD64_REL32_5:
		relativeSymbolDefAddress := symbolDefAddress - (uintptr)(reloc.Type-4) - (absoluteSymbolAddress + 4)
		addr := (*uint32)(unsafe.Pointer(absoluteSymbolAddress))
		fmt.Sprintf("Symbol Ref Address: 0x%x\n", addr)
		*addr = uint32(relativeSymbolDefAddress)
	default:
		fmt.Printf("Unsupported relocation type: %d\n", reloc.Type)
	}
}

type CoffSection struct {
	Section *pecoff.Section
	Address uintptr
}

func Load(coffBytes []byte, argBytes []byte) (string, error) {
	return LoadWithMethod(coffBytes, argBytes, "go")
}

func LoadWithMethod(coffBytes []byte, argBytes []byte, method string) (string, error) {
	output := make(chan interface{})

	parsedCoff := pecoff.Explore(binutil.WrapByteSlice(coffBytes))
	parsedCoff.ReadAll()
	parsedCoff.Seal()

	sections := make(map[string]CoffSection, parsedCoff.Sections.Len())

	gotBaseAddress := uintptr(0)
	gotOffset := 0
	gotSize := uint32(0)
	var gotMap = make(map[string]uintptr)

	bssBaseAddress := uintptr(0)
	bssOffset := 0
	bssSize := uint32(0)

	for _, symbol := range parsedCoff.Symbols {
		if isSpecialSymbol(symbol) {
			if isImportSymbol(symbol) {
				gotSize += 8
			} else {
				bssSize += symbol.Value + 8 //leave room for null bytes
			}
		}
	}

	for _, section := range parsedCoff.Sections.Array() {
		allocationSize := uintptr(section.SizeOfRawData)
		if strings.HasPrefix(section.NameString(), ".bss") {
			allocationSize = uintptr(bssSize)
		}

		if allocationSize == 0 {
			continue
		}

		addr, err := virtualAlloc(0, allocationSize, MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN, PAGE_READWRITE)
		if err != nil {
			return "", fmt.Errorf("VirtualAlloc failed: %s", err.Error())
		}

		if strings.HasPrefix(section.NameString(), ".bss") {
			bssBaseAddress = addr
		}

		copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:], section.RawData())

		allocatedSection := CoffSection{
			Section: section,
			Address: addr,
		}

		sections[section.NameString()] = allocatedSection
	}

	gotBaseAddress, err := virtualAlloc(0, uintptr(gotSize), MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN, PAGE_READWRITE)
	if err != nil {
		return "", fmt.Errorf("VirtualAlloc failed: %s", err.Error())
	}

	for _, section := range parsedCoff.Sections.Array() {
		sectionVirtualAddr := sections[section.NameString()].Address
		fmt.Sprintf("Section: %s\n", section.NameString())

		for _, reloc := range section.Relocations() {

			symbol := parsedCoff.Symbols[reloc.SymbolTableIndex]

			if symbol.StorageClass > 3 {
				continue
			}

			symbolTypeString := windef.MAP_IMAGE_SYM_CLASS[symbol.StorageClass]
			fmt.Sprintf("0x%08X %s %s\n", reloc.VirtualAddress, symbolTypeString, symbol.NameString())
			symbolDefAddress := uintptr(0)

			if isSpecialSymbol(symbol) {
				if isImportSymbol(symbol) {
					externalAddress := resolveExternalAddress(symbol.NameString(), output)

					if externalAddress == 0 {
						return "", fmt.Errorf("failed to resolve external address for symbol: %s", symbol.NameString())
					}

					if existingGotAddress, exists := gotMap[symbol.NameString()]; exists {
						symbolDefAddress = existingGotAddress
					} else {
						symbolDefAddress = gotBaseAddress + uintptr(gotOffset*8)
						gotOffset += 1
						gotMap[symbol.NameString()] = symbolDefAddress
					}
					copy((*[8]byte)(unsafe.Pointer(symbolDefAddress))[:], (*[8]byte)(unsafe.Pointer(&externalAddress))[:])
				} else {
					symbolDefAddress = bssBaseAddress + uintptr(bssOffset)
					bssOffset += int(symbol.Value) + 8
				}
			} else {
				targetSection := parsedCoff.Sections.Array()[symbol.SectionNumber-1]
				symbolDefAddress = sections[targetSection.NameString()].Address + uintptr(symbol.Value)
			}

			fmt.Sprintf("Symbol Def Address: 0x%x\n", symbolDefAddress)
			processRelocation(symbolDefAddress, sectionVirtualAddr, reloc, symbol)
		}

		if section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
			oldProtect := PAGE_READWRITE
			_, _, errVirtualProtect := procVirtualProtect.Call(sectionVirtualAddr, uintptr(section.SizeOfRawData), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
			if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
				return "", fmt.Errorf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error())
			}
		}
	}

	// Call the entry point
	go invokeMethod(method, argBytes, parsedCoff, sections, output)

	bofOutput := ""
	for msg := range output {
		bofOutput += msg.(string) + "\n"
	}
	return bofOutput, nil
}

func invokeMethod(methodName string, argBytes []byte, parsedCoff *pecoff.File, sectionMap map[string]CoffSection, outChannel chan<- interface{}) {
	defer close(outChannel)

	// Catch unexpected panics and propagate them to the output channel
	// This prevents the host program from terminating unexpectedly
	defer func() {
		if r := recover(); r != nil {
			errorMsg := fmt.Sprintf("Panic occurred when executing COFF: %v\n%s", r, debug.Stack())
			outChannel <- errorMsg
		}
	}()

	// Call the entry point
	for _, symbol := range parsedCoff.Symbols {
		if symbol.NameString() == methodName {
			mainSection := parsedCoff.Sections.Array()[symbol.SectionNumber-1]
			entryPoint := sectionMap[mainSection.NameString()].Address + uintptr(symbol.Value)

			if len(argBytes) == 0 {
				argBytes = make([]byte, 1)
			}
			syscall.SyscallN(entryPoint, uintptr(unsafe.Pointer(&argBytes[0])), uintptr((len(argBytes))))
		}
	}
}
