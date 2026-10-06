// 手工拼公钥行，供测试与场景使用。
package sshkey

import (
	"encoding/base64"
	"encoding/binary"
)

func Blob(fields ...[]byte) []byte {
	buf := []byte{}
	for _, field := range fields {
		head := make([]byte, 4)
		binary.BigEndian.PutUint32(head, uint32(len(field)))
		buf = append(buf, head...)
		buf = append(buf, field...)
	}
	return buf
}

func Line(algo string, material []byte, comment string) string {
	blob := Blob([]byte(algo), material)
	out := algo + " " + base64.StdEncoding.EncodeToString(blob)
	if comment != "" {
		out += " " + comment
	}
	return out
}
