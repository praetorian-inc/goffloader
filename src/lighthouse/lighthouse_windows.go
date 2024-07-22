/*
	Our Beacon* Function Compatibilty implementations. Code here is taken very liberally
    from Ne0nd0g's go-coff project at https://github.com/Ne0nd0g/go-coff.

	Beacon function names are signatured to hell and back in yara land so this package is
    called "lighthouse" to avoid the presence of beacon/BOF strings in the generated binary.
    Function names have also been replaced/reduced along to avoid detection.
*/

package lighthouse

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/praetorian-inc/goffloader/src/memory"
	"golang.org/x/sys/windows"
	"strconv"
	"strings"
	"unicode/utf16"
	"unsafe"
)

func GetCoffOutputForChannel(channel chan<- interface{}) func(int, uintptr, int) uintptr {
	return func(beaconType int, data uintptr, length int) uintptr {
		if length <= 0 {
			return 0
		}
		out := memory.ReadBytesFromPtr(data, uint32(length))

		channel <- string(out)
		return 1
	}
}

func GetCoffPrintfForChannel(channel chan<- interface{}) func(int, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) uintptr {
	return func(beaconType int, data uintptr, arg0 uintptr, arg1 uintptr, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr, arg6 uintptr, arg7 uintptr, arg8 uintptr, arg9 uintptr) uintptr {
		var out string
		out = memory.ReadCStringFromPtr(data)
		numArgs := strings.Count(out, "%")
		args := []uintptr{arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9}

		fString := ""
		argOffset := 0
		skipChar := false
		for i := range len(out) {
			c := out[i]

			if skipChar {
				skipChar = false
				continue
			}

			if argOffset > numArgs {
				fString += string(c)
				continue
			}

			if c == '%' && i < len(out)-1 {
				d := out[i+1]
				switch d {
				case 's':
					s := memory.ReadCStringFromPtr(args[argOffset])
					// no way to tell if the string is unicode or ansi formatted, so assume if we read
					// more than 4 characters without a null byte that it's ANSI
					if len(s) < 5 {
						s = memory.ReadWStringFromPtr(args[argOffset])
					}
					fString += s
				case 'p':
					fString += fmt.Sprintf("%x", unsafe.Pointer(args[argOffset]))
				default:
					fString += fmt.Sprintf("%"+string(d), args[argOffset])
				}
				argOffset++
				skipChar = true
			} else {
				fString += string(c)
			}
		}

		//fmt.Printf("%s\n", fString) //uncomment for debugging failed BOF/Executable runs
		channel <- fString
		return 0
	}
}

type DataParser struct {
	original uintptr
	buffer   uintptr
	length   uint32
	size     uint32
}

func DataExtract(datap *DataParser, size *uint32) uintptr {
	if datap.length <= 0 {
		return 0
	}

	binaryLength := *(*uint32)(unsafe.Pointer(datap.buffer))
	datap.buffer += uintptr(4)
	datap.length -= 4
	if datap.length < binaryLength {
		return 0
	}

	out := make([]byte, binaryLength)
	memory.CopyMemory(uintptr(unsafe.Pointer(&out[0])), datap.buffer, binaryLength)
	if uintptr(unsafe.Pointer(size)) != uintptr(0) && binaryLength != 0 {
		*size = binaryLength
	}

	datap.buffer += uintptr(binaryLength)
	datap.length -= binaryLength
	return uintptr(unsafe.Pointer(&out[0]))
}

func DataInt(datap *DataParser) uintptr {
	value := memory.ReadUIntFromPtr(datap.buffer)
	datap.buffer += uintptr(4)
	datap.length -= 4
	return uintptr(value)
}

func DataLength(datap *DataParser) uintptr {
	return uintptr(datap.length)
}

func DataParse(datap *DataParser, buff uintptr, size uint32) uintptr {
	if size <= 0 {
		return 0
	}
	datap.original = buff
	datap.buffer = buff + uintptr(4)
	datap.length = size - 4
	datap.size = size - 4
	return 1
}

func DataShort(datap *DataParser) uintptr {
	if datap.length < 2 {
		return 0
	}

	value := memory.ReadShortFromPtr(datap.buffer)
	datap.buffer += uintptr(2)
	datap.length -= 2
	return uintptr(value)
}

var keyStore = make(map[string]uintptr, 0)

func AddValue(key uintptr, ptr uintptr) uintptr {
	sKey := memory.ReadCStringFromPtr(key)
	keyStore[sKey] = ptr
	return uintptr(1)
}

func GetValue(key uintptr) uintptr {
	sKey := memory.ReadCStringFromPtr(key)
	if value, exists := keyStore[sKey]; exists {
		return value
	}
	return uintptr(0)
}

func RemoveValue(key uintptr) uintptr {
	sKey := memory.ReadCStringFromPtr(key)
	if _, exists := keyStore[sKey]; exists {
		delete(keyStore, sKey)
		return uintptr(1)
	}
	return uintptr(0)
}

func PackArgs(data []string) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var buff []byte
	for _, arg := range data {
		switch arg[0] {
		case 'b':
			data, err := PackBinary(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("Binary packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'i':
			data, err := PackIntString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("Int packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
			}
			buff = append(buff, data...)
		case 's':
			data, err := PackShortString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("Short packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'z':
			var packedData []byte
			var err error
			// Handler for packing empty strings
			if len(arg) < 2 {
				packedData, _ = PackString("")
			} else {
				packedData, err = PackString(arg[1:])
				if err != nil {
					return nil, fmt.Errorf("String packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
				}
			}
			buff = append(buff, packedData...)
		case 'Z':
			var packedData []byte
			var err error
			if len(arg) < 2 {
				packedData, _ = PackWideString("")
			} else {
				packedData, err = PackWideString(arg[1:])
				if err != nil {
					return nil, fmt.Errorf("WString packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
				}
			}
			buff = append(buff, packedData...)
		default:
			return nil, fmt.Errorf("Data must be prefixed with 'b', 'i', 's','z', or 'Z'\n")
		}
	}
	rData := make([]byte, 4)
	binary.LittleEndian.PutUint32(rData, uint32(len(buff)))
	rData = append(rData, buff...)
	return rData, nil
}

func PackBinary(data string) ([]byte, error) {
	hexData, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(hexData)))
	buff = append(buff, hexData...)
	return buff, nil
}

func PackInt(i uint32) ([]byte, error) {
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(i))
	return buff, nil
}

func PackIntString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, err
	}
	return PackInt(uint32(i))
}

func PackShort(i uint16) ([]byte, error) {
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, uint16(i))
	return buff, nil
}

func PackShortString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, err
	}
	return PackShort(uint16(i))
}

func PackString(s string) ([]byte, error) {
	d, err := windows.UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(d)))
	for _, c := range d {
		buff = append(buff, byte(c))
	}
	return buff, nil
}

func convertToWindowsUnicode(s string) []byte {
	runes := []rune(s)
	utf16Encoded := utf16.Encode(runes)
	buf := make([]byte, len(utf16Encoded)*2)
	for i, utf16Char := range utf16Encoded {
		binary.LittleEndian.PutUint16(buf[i*2:], utf16Char)
	}
	return buf
}

func PackWideString(s string) ([]byte, error) {
	d := convertToWindowsUnicode(s)
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(d)))
	buff = append(buff, d...)
	return buff, nil
}
