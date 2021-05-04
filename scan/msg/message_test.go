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
			out := scan.Lex([]byte(k), lexMessage)
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
		{":gossip ERROR :Closing link\r\n",
			&Message{
				nick:        "gossip",
				Command:     "ERROR",
				Params:      []string{"Closing link"},
				trailingSet: true,
			},
		},
	}

	for _, v := range tests {
		t.Run(v.s, func(t *testing.T) {
			if v.s != v.m.String() {
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
				nick:        "dan",
				user:        "d",
				host:        "localhost",
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
				nick:        "dan",
				user:        "d",
				host:        "123.456.789",
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
			out := Parse([]byte(v.s))
			if !reflect.DeepEqual(out, v.m) {
				t.Error("parse error", out, v.m)
			}
		})
	}
}

func TestParseTags(t *testing.T) {
	tests := []struct {
		input string
		tags  map[string]TagVal
	}{
		{":nick!ident@host.com PRIVMSG me :Hello\r\n", nil},
		{"@aaa=bbb;ccc :nick!ident@host.com PRIVMSG me :Hello\r\n", map[string]TagVal{
			"aaa": {Value: "bbb"},
			"ccc": {Value: ""},
		}},
		{"@+example-client-tag=example-value TAGMSG @#channel\r\n", map[string]TagVal{
			"example-client-tag": {Value: "example-value", ClientPrefix: true},
		}},
		{"@aaa=bbb;ccc;example.com/ddd=eee :nick!ident@host.com PRIVMSG me :Hello\r\n", map[string]TagVal{
			"aaa": {Value: "bbb"},
			"ccc": {Value: ""},
			"ddd": {Value: "eee", Vendor: "example.com"},
		}},
		{"@+example-client-tag=example-value PRIVMSG #channel :Message\r\n", map[string]TagVal{
			"example-client-tag": {ClientPrefix: true, Value: "example-value"},
		}},
		{"@+example.com/foo=bar :irc.example.com NOTICE #channel :A vendor-prefixed client-only tagged message\r\n", map[string]TagVal{
			"foo": {ClientPrefix: true, Value: "bar", Vendor: "example.com"},
		}},
		{"@+example=raw+:=,escaped\\:\\s\\\\ :irc.example.com NOTICE #channel :Message\r\n", map[string]TagVal{
			"example": {ClientPrefix: true, Value: "raw+:=,escaped\\:\\s\\\\"},
		}},
	}

	for _, v := range tests {
		t.Run(v.input, func(t *testing.T) {
			out := Parse([]byte(v.input))
			if !reflect.DeepEqual(out.tags, v.tags) {
				t.Error("parse error", out.tags, v.tags)
			}
		})
	}
}

func TestTagRaw(t *testing.T) {
	tests := []struct {
		input   TagVal
		escaped string
	}{
		{TagVal{Value: "raw+:=,escaped\\:\\s\\\\"}, "raw+:=,escaped; \\"},
	}

	for _, v := range tests {
		t.Run(v.input.Value, func(t *testing.T) {
			if v.input.Raw() != v.escaped {
				t.Error("unescaped incorrectly")
			}
		})
	}
}
