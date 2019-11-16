package util

import "encoding/binary"

func Htons(val uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, val)
	return b
}

func ByteToInt(b []byte) int {
	return int(binary.BigEndian.Uint16(b))
}
