package msg

import (
	"testing"

	"github.com/mitchr/gossip/scan"
)

func TestMessageString(t *testing.T) {
	tests := []struct {
		s string
		m *Message
	}{
		{"CAP LS :302\r\n", &Message{
			Command:     "CAP",
			Params:      []string{"LS", "302"},
			trailingSet: true,
		}},
		{"CAP LS 302\r\n", &Message{
			Command: "CAP",
			Params:  []string{"LS", "302"},
		}},
		{":gossip ERROR :Closing link\r\n", &Message{
			Nick:        "gossip",
			Command:     "ERROR",
			Params:      []string{"Closing link"},
			trailingSet: true,
		}},
		{":alice REHASH\r\n", &Message{
			Nick:    "alice",
			Command: "REHASH",
		}},
		{"@example.com/a=bb :nick!ident@host.com PRIVMSG me :Hello\r\n",
			&Message{
				Nick:        "nick",
				User:        "ident",
				Host:        "host.com",
				Command:     "PRIVMSG",
				Params:      []string{"me", "Hello"},
				trailingSet: true,
				tags: []Tag{
					{false, "example.com/a", "bb"},
				}},
		},
	}

	for _, v := range tests {
		t.Run(v.s, func(t *testing.T) {
			if v.s != v.m.String() {
				t.Log([]byte(v.s), "\n", []byte(v.m.String()))
				t.Error(v.s, v.m.String())
			}
		})
	}
}

func TestTagRaw(t *testing.T) {
	tests := []struct {
		input   Tag
		escaped string
	}{
		{Tag{Value: "raw+:=,escaped\\:\\s\\\\"}, "raw+:=,escaped; \\"},
	}

	for _, v := range tests {
		t.Run(v.input.Value, func(t *testing.T) {
			if v.input.Raw() != v.escaped {
				t.Error("unescaped incorrectly")
			}
		})
	}
}

func TestMessageFormat(t *testing.T) {
	m := &Message{
		Nick:        "dan",
		User:        "d",
		Host:        "localhost",
		Command:     "PRIVMSG",
		Params:      []string{"%s%s", "%s!"},
		trailingSet: true,
	}

	formattedM := m.Format("#chan", "b", "Hey")
	if formattedM.String() != ":dan!d@localhost PRIVMSG #chanb :Hey!\r\n" {
		t.Log(formattedM.String())
		t.Fail()
	}
}

func TestSetMsgid(t *testing.T) {
	m := &Message{
		Nick:        "dan",
		User:        "d",
		Host:        "localhost",
		Command:     "PRIVMSG",
		Params:      []string{"%s%s", "%s!"},
		trailingSet: true,
	}

	m.SetMsgid()
	initVal := m.tags[0].Value

	m.SetMsgid()
	finalVal := m.tags[0].Value

	if initVal != finalVal || len(m.tags) != 1 {
		t.Error("msgid set twice")
	}
}

var testInput []byte = []byte("@a=b :bob!Bob@example.com PRIVMSG alice :Welcome to the server!\r\n")

func BenchmarkLex(b *testing.B) {
	for i := 0; i < b.N; i++ {
		l := scan.Lex(testInput, LexMessage)
		for tok, _ := l.PeekToken(); tok != scan.EOFToken; tok, _ = l.PeekToken() {
			l.NextToken()
		}
	}
}

func BenchmarkMessageBytes(b *testing.B) {
	m := &Message{
		Nick:        "nick",
		User:        "ident",
		Host:        "host.com",
		Command:     "PRIVMSG",
		Params:      []string{"me", "Hello"},
		trailingSet: true,
		tags: []Tag{
			{false, "example.com/a", "bb"},
		}}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = m.Bytes()
	}
}
