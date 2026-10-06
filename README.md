# ssh-key-line

解析 OpenSSH 公钥行：算法名 + base64 密钥块 + 可选备注。只用标准库。

```
go test ./...
go vet ./...
go run ./cmd/sshkey --sample=comment
go run ./cmd/sshkey --sample=trailing
go run ./cmd/sshkey --sample=mismatch
go run ./cmd/sshkey --sample=work
```

## 口径

- **行结构**：空格分开的算法名、base64 密钥块、可选备注。
- **base64**：按标准字母表解码。
- **密钥块**：一串长度前缀字段，每个字段 4 字节大端长度加内容；字段越界或者块尾还有多余字节都是坏行。
- **备注**：算法名与 base64 之后的整段内容（可以含空格）。
- **一致性**：块里第一个字段（算法名）必须和行首那个一致。
- **去重**：同一算法同一密钥材料只算一条。

## 不变量

- 解析出的算法名同时来自行首与密钥块时两者一致。
- 单个密钥占据的字节数与块内字段一致。
- `scanned` 不随行数平方级放大：两千行的 `scanned` 不超过 9000。

## 输出契约

每个场景打印一行 JSON；`--sample=work` 只打印 `{"lines": N, "keys": N, "scanned": N}`。
