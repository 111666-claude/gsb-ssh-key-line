package sshkey

import (
	"encoding/base64"
)

func Material(n int, fill byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = fill
	}
	return out
}

// SpacedCommentLine 造一条备注里带空格的公钥行。
func SpacedCommentLine() string {
	return Line("ssh-ed25519", Material(32, 7), "work laptop key")
}

// TrailingLine 造一条密钥块尾部多出字节的公钥行。
func TrailingLine() string {
	blob := append(Blob([]byte("ssh-ed25519"), Material(32, 3)), 0xAA, 0xBB)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " extra@host"
}

// MismatchLine 造一条行首算法与字段里算法不一致的密钥行。
func MismatchLine() string {
	blob := Blob([]byte("ssh-ed25519"), Material(32, 1))
	return "ssh-rsa " + base64.StdEncoding.EncodeToString(blob) + " odd@host"
}
