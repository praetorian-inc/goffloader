package memory

import "unsafe"

func CopyMemory(dst, src uintptr, length uint32) {
	copy((*[1 << 30]byte)(unsafe.Pointer(dst))[:length], (*[1 << 30]byte)(unsafe.Pointer(src))[:length])
}

func ReadBytesFromPtr(src uintptr, length uint32) []byte {
	out := make([]byte, length)
	CopyMemory(uintptr(unsafe.Pointer(&out[0])), src, length)
	return out
}

func ReadUIntFromPtr(src uintptr) uint32 {
	return *(*uint32)(unsafe.Pointer(src))
}

func ReadShortFromPtr(src uintptr) uint16 {
	return *(*uint16)(unsafe.Pointer(src))
}

func ReadCStringFromPtr(src uintptr) string {
	if src == 0 {
		return ""
	}
	str := ""
	offset := 0
	for {
		c := *(*byte)(unsafe.Pointer(src + uintptr(offset)))
		if c == 0 {
			break
		}
		str += string(c)
		offset++
	}
	return str
}

func ReadWStringFromPtr(src uintptr) string {
	if src == 0 {
		return ""
	}
	str := ""
	offset := 0
	for {
		c1 := *(*byte)(unsafe.Pointer(src + uintptr(offset)))
		c2 := *(*byte)(unsafe.Pointer(src + uintptr(offset+1)))
		if c1 == 0 && c2 == 0 {
			break
		}
		str += string(c1) + string(c2)
		offset += 2
	}
	return str
}
