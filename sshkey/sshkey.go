// Package sshkey 解析 OpenSSH 公钥行。
package sshkey

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// Key 是一条解析出来的公钥。
type Key struct {
	Algo    string `json:"algo"`
	Bytes   int    `json:"bytes"`
	Comment string `json:"comment"`
	FP      string `json:"fp"`
}

// Counter 记录本轮检查过的已解析条数。
type Counter struct {
	Scanned int
}

func readField(blob []byte, off *int) ([]byte, error) {
	if *off+4 > len(blob) {
		return nil, errors.New("truncated")
	}
	n := int(binary.BigEndian.Uint32(blob[*off : *off+4]))
	*off += 4
	if n < 0 || *off+n > len(blob) {
		return nil, errors.New("truncated")
	}
	value := blob[*off : *off+n]
	*off += n
	return value, nil
}

// Parse 解析一行公钥。
func Parse(line string, c *Counter) (Key, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return Key{}, errors.New("bad-line")
	}
	blob, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return Key{}, errors.New("bad-base64")
	}
	off := 0
	algo, err := readField(blob, &off)
	if err != nil {
		return Key{}, err
	}
	material, err := readField(blob, &off)
	if err != nil {
		return Key{}, err
	}
	comment := ""
	if len(parts) > 2 {
		comment = parts[2]
	}
	sum := 0
	for _, b := range material {
		sum = sum*31 + int(b)
	}
	return Key{
		Algo:    string(algo),
		Bytes:   len(material),
		Comment: comment,
		FP:      hex.EncodeToString([]byte{byte(sum), byte(sum >> 8)}),
	}, nil
}

// ParseMany 逐行解析并按指纹去重。
func ParseMany(lines []string, c *Counter) []Key {
	out := []Key{}
	for _, line := range lines {
		key, err := Parse(line, c)
		if err != nil {
			continue
		}
		dup := false
		for _, seen := range out {
			c.Scanned++
			if seen.FP == key.FP && seen.Algo == key.Algo {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, key)
		}
	}
	return out
}
