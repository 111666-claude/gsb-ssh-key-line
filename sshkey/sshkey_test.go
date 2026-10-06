package sshkey

import "testing"

func TestSimpleLine(t *testing.T) {
	line := Line("ssh-ed25519", Material(32, 1), "me@host")
	key, err := Parse(line, &Counter{})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if key.Algo != "ssh-ed25519" || key.Bytes != 32 || key.Comment != "me@host" {
		t.Fatalf("字段不对：%+v", key)
	}
}

func TestBadBase64(t *testing.T) {
	if _, err := Parse("ssh-ed25519 !!!", &Counter{}); err == nil {
		t.Fatal("base64 不合法应报错")
	}
}

func TestShortLine(t *testing.T) {
	if _, err := Parse("ssh-ed25519", &Counter{}); err == nil {
		t.Fatal("缺字段应报错")
	}
}

func TestCommentIsOptional(t *testing.T) {
	key, err := Parse(Line("ssh-ed25519", Material(32, 2), ""), &Counter{})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if key.Comment != "" {
		t.Fatalf("没有备注时应为空：%+v", key)
	}
}

func TestParseManyKeepsDistinct(t *testing.T) {
	lines := []string{
		Line("ssh-ed25519", Material(32, 1), "a"),
		Line("ssh-ed25519", Material(32, 2), "b"),
	}
	if got := ParseMany(lines, &Counter{}); len(got) != 2 {
		t.Fatalf("两条不同密钥应都保留：%+v", got)
	}
}
