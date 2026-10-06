// Command sshkey 是公钥行解析的场景入口。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"example.com/ssh-key-line/sshkey"
)

func emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}

func main() {
	sample := flag.String("sample", "", "comment|trailing|mismatch|work")
	flag.Parse()

	c := &sshkey.Counter{}
	switch *sample {
	case "comment":
		key, err := sshkey.Parse(sshkey.SpacedCommentLine(), c)
		if err != nil {
			emit(map[string]string{"error": err.Error()})
			return
		}
		emit(map[string]string{"comment": key.Comment})
	case "trailing":
		key, err := sshkey.Parse(sshkey.TrailingLine(), c)
		if err != nil {
			emit(map[string]string{"error": err.Error()})
			return
		}
		emit(map[string]string{"algo": key.Algo})
	case "mismatch":
		key, err := sshkey.Parse(sshkey.MismatchLine(), c)
		if err != nil {
			emit(map[string]string{"error": err.Error()})
			return
		}
		emit(map[string]string{"algo": key.Algo})
	case "work":
		lines := []string{}
		for i := 0; i < 2000; i++ {
			lines = append(lines, sshkey.Line("ssh-ed25519", sshkey.Material(32, byte(i%251+1)),
				fmt.Sprintf("u%d", i)))
		}
		keys := sshkey.ParseMany(lines, c)
		emit(map[string]int{"lines": 2000, "keys": len(keys), "scanned": c.Scanned})
	default:
		fmt.Fprintln(os.Stderr, "未知场景："+*sample)
		os.Exit(2)
	}
	_ = strings.TrimSpace
}
