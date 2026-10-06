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
	Algo     string `json:"algo"`
	Bytes    int    `json:"bytes"`
	Comment  string `json:"comment"`
	FP       string `json:"fp"`
	material []byte
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
	rest := strings.TrimLeft(line, " \t")
	algoEnd := strings.IndexAny(rest, " \t")
	if algoEnd < 0 {
		return Key{}, errors.New("bad-line")
	}
	lineAlgo := rest[:algoEnd]
	rest = strings.TrimLeft(rest[algoEnd:], " \t")
	b64End := strings.IndexAny(rest, " \t")
	var b64, comment string
	if b64End < 0 {
		b64 = rest
	} else {
		b64 = rest[:b64End]
		comment = strings.TrimLeft(rest[b64End:], " \t")
	}
	if lineAlgo == "" || b64 == "" {
		return Key{}, errors.New("bad-line")
	}
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return Key{}, errors.New("bad-base64")
	}
	off := 0
	algo, err := readField(blob, &off)
	if err != nil {
		return Key{}, err
	}
	if string(algo) != lineAlgo {
		return Key{}, errors.New("algo-mismatch")
	}
	material, err := readField(blob, &off)
	if err != nil {
		return Key{}, err
	}
	for off < len(blob) {
		if _, err := readField(blob, &off); err != nil {
			return Key{}, errors.New("trailing-bytes")
		}
	}
	sum := 0
	for _, b := range material {
		sum = sum*31 + int(b)
	}
	return Key{
		Algo:     string(algo),
		Bytes:    len(material),
		Comment:  comment,
		FP:       hex.EncodeToString([]byte{byte(sum), byte(sum >> 8)}),
		material: material,
	}, nil
}

// ParseMany 逐行解析并按指纹去重。
func ParseMany(lines []string, c *Counter) []Key {
	out := []Key{}
	seen := make(map[string]struct{})
	for _, line := range lines {
		key, err := Parse(line, c)
		if err != nil {
			continue
		}
		c.Scanned++
		id := key.Algo + "\x1f" + string(key.material)
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			out = append(out, key)
		}
	}
	return out
}
