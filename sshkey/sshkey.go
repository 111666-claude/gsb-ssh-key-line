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

	material string
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
	if n < 0 || n > len(blob)-*off {
		return nil, errors.New("truncated")
	}
	value := blob[*off : *off+n]
	*off += n
	return value, nil
}

// splitLine 把一行拆成算法名、base64 密钥块和整段备注。
func splitLine(line string) (algo, blob, comment string, err error) {
	rest := strings.TrimLeft(line, " \t")
	i := strings.IndexAny(rest, " \t")
	if i < 0 {
		return "", "", "", errors.New("bad-line")
	}
	algo = rest[:i]
	rest = strings.TrimLeft(rest[i:], " \t")
	j := strings.IndexAny(rest, " \t")
	if j < 0 {
		return algo, rest, "", nil
	}
	return algo, rest[:j], strings.TrimSpace(rest[j:]), nil
}

// decodeBase64 按标准字母表解码，允许末尾缺补齐。
func decodeBase64(s string) ([]byte, error) {
	if rem := len(s) % 4; rem != 0 {
		s += strings.Repeat("=", 4-rem)
	}
	return base64.StdEncoding.DecodeString(s)
}

// Parse 解析一行公钥。
func Parse(line string, c *Counter) (Key, error) {
	algo, blob64, comment, err := splitLine(line)
	if err != nil {
		return Key{}, err
	}
	blob, err := decodeBase64(blob64)
	if err != nil {
		return Key{}, errors.New("bad-base64")
	}
	off := 0
	algoField, err := readField(blob, &off)
	if err != nil {
		return Key{}, err
	}
	material, err := readField(blob, &off)
	if err != nil {
		return Key{}, err
	}
	if off != len(blob) {
		return Key{}, errors.New("trailing-bytes")
	}
	if string(algoField) != algo {
		return Key{}, errors.New("algo-mismatch")
	}
	sum := 0
	for _, b := range material {
		sum = sum*31 + int(b)
	}
	return Key{
		Algo:     algo,
		Bytes:    len(material),
		Comment:  comment,
		FP:       hex.EncodeToString([]byte{byte(sum), byte(sum >> 8)}),
		material: string(material),
	}, nil
}

// ParseMany 逐行解析并按指纹去重。
func ParseMany(lines []string, c *Counter) []Key {
	out := []Key{}
	seen := map[string]struct{}{}
	for _, line := range lines {
		key, err := Parse(line, c)
		if err != nil {
			continue
		}
		c.Scanned++
		id := key.Algo + "\x00" + key.material
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, key)
	}
	return out
}
