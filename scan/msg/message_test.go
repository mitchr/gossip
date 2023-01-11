package msg

import (
	"reflect"
	"testing"

	"github.com/mitchr/gossip/scan"
)

func TestLexParams(t *testing.T) {
	tests := map[string][]scan.Token{
		// 	" CAP * LIST\r\n": {
		// 		{TokenType: space, Value: " "},
		// 		{TokenType: nospcrlfcl, Value: "CAP"},
		// 		{TokenType: space, Value: " "},
		// 		{TokenType: nospcrlfcl, Value: "*"},
		// 		{TokenType: space, Value: " "},
		// 		{TokenType: nospcrlfcl, Value: "LIST"},
		// 		{TokenType: crlf, Value: "\r\n"},
		// 	},
		// 	" * LS :multi-prefix sasl\r\n": {
		// 		{TokenType: space, Value: " "},
		// 		{TokenType: nospcrlfcl, Value: "*"},
		// 		{TokenType: space, Value: " "},
		// 		{TokenType: nospcrlfcl, Value: "LS"},
		// 		{TokenType: space, Value: " "},
		// 		{TokenType: colon, Value: ":"},
		// 		{TokenType: nospcrlfcl, Value: "multi-prefix"},
		// 		{TokenType: space, Value: " "},
		// 		{TokenType: nospcrlfcl, Value: "sasl"},
		// 		{TokenType: crlf, Value: "\r\n"},
		// 	},
	}

	for k, v := range tests {
		t.Run(k, func(t *testing.T) {
			out, _ := scan.Lex([]byte(k), lexMessage)
			if !reflect.DeepEqual(out, v) {
				t.Error("lex error:", out, v)
			}
		})
	}
}

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

func TestParseMessage(t *testing.T) {
	tests := []struct {
		s string
		m *Message
	}{
		{":dan!d@localhost PRIVMSG #chan :Hey!\r\n",
			&Message{
				Nick:        "dan",
				User:        "d",
				Host:        "localhost",
				Command:     "PRIVMSG",
				Params:      []string{"#chan", "Hey!"},
				trailingSet: true,
			},
		},
		{"NICK alice\r\n",
			&Message{
				Command: "NICK",
				Params:  []string{"alice"},
			},
		},
		{":dan!d@123.456.789 QUIT :Quit: Bye for now!\r\n",
			&Message{
				Nick:        "dan",
				User:        "d",
				Host:        "123.456.789",
				Command:     "QUIT",
				Params:      []string{"Quit: Bye for now!"},
				trailingSet: true,
			},
		},
		{"USER alice 0 * :Alice Smith\r\n",
			&Message{
				Command:     "USER",
				Params:      []string{"alice", "0", "*", "Alice Smith"},
				trailingSet: true,
			},
		},
		{"PING [::]:6667\r\n",
			&Message{
				Command:     "PING",
				Params:      []string{"[::]:6667"},
				trailingSet: false,
			},
		},
		{"", nil},
		// {lex([]byte("CAP * LS :multi-prefix sasl\r\n"))},
		// {lex([]byte("CAP REQ :sasl message-tags foo\r\n"))},
	}

	for _, v := range tests {
		t.Run(v.s, func(t *testing.T) {
			toks, _ := scan.Lex([]byte(v.s), lexMessage)
			out, _ := Parse(toks)
			if !reflect.DeepEqual(out, v.m) {
				t.Error("parse error", out, v.m)
			}
		})
	}
}

func TestParseTags(t *testing.T) {
	tests := []struct {
		input string
		tags  []Tag
	}{
		{":nick!ident@host.com PRIVMSG me :Hello\r\n", nil},
		{"@aaa=bbb;ccc :nick!ident@host.com PRIVMSG me :Hello\r\n", []Tag{
			{false, "aaa", "bbb"},
			{false, "ccc", ""},
		}},
		{"@+example-client-tag=example-value TAGMSG @#channel\r\n", []Tag{
			{true, "example-client-tag", "example-value"},
		}},
		{"@aaa=bbb;ccc;example.com/ddd=eee :nick!ident@host.com PRIVMSG me :Hello\r\n", []Tag{
			{false, "aaa", "bbb"},
			{false, "ccc", ""},
			{false, "example.com/ddd", "eee"},
		}},
		{"@+example-client-tag=example-value PRIVMSG #channel :Message\r\n", []Tag{
			{true, "example-client-tag", "example-value"},
		}},
		{"@+example.com/foo=bar :irc.example.com NOTICE #channel :A vendor-prefixed client-only tagged message\r\n", []Tag{
			{true, "example.com/foo", "bar"},
		}},
		{"@+example=raw+:=,escaped\\:\\s\\\\ :irc.example.com NOTICE #channel :Message\r\n", []Tag{
			{true, "example", "raw+:=,escaped\\:\\s\\\\"},
		}},
	}

	for _, v := range tests {
		t.Run(v.input, func(t *testing.T) {
			toks, _ := scan.Lex([]byte(v.input), lexMessage)
			out, err := Parse(toks)
			if err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(out.tags, v.tags) {
				t.Error("parse error", out.tags, v.tags)
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

var testInput []byte = []byte("@a=b :bob!Bob@example.com PRIVMSG alice :Welcome to the server!\r\n")

func BenchmarkLex(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Lex(testInput)
	}
}

func BenchmarkParse(b *testing.B) {
	tokens, _ := Lex(testInput)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Parse(tokens)
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
