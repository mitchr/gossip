package msg

import (
	"cmp"
	"reflect"
	"slices"
	"testing"

	"github.com/mitchr/gossip/scan"
)

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
		{"PRIVMSG bob :  hi bob!\r\n",
			&Message{
				Command:     "PRIVMSG",
				Params:      []string{"bob", "  hi bob!"},
				trailingSet: true,
			},
		},
		{"", nil},
		// {lex([]byte("CAP * LS :multi-prefix sasl\r\n"))},
		// {lex([]byte("CAP REQ :sasl message-tags foo\r\n"))},
	}

	for _, v := range tests {
		t.Run(v.s, func(t *testing.T) {
			out, _ := Parse(&scan.Parser{Lexer: scan.Lex([]byte(v.s), LexMessage)})
			if !reflect.DeepEqual(out, v.m) {
				t.Error("parse error; wanted", v.m, "but got", out)
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
	}

	for _, v := range tests {
		t.Run(v.input, func(t *testing.T) {
			out, err := Parse(&scan.Parser{Lexer: scan.Lex([]byte(v.input), LexMessage)})
			if err != nil {
				t.Error(err)
			}

			slices.SortFunc(out.tags, func(t1, t2 Tag) int {
				return cmp.Compare(t1.Key, t2.Key)
			})
			if !reflect.DeepEqual(out.tags, v.tags) {
				t.Error("parse error; wanted", v.tags, "but got", out.tags)
			}
		})
	}
}

func BenchmarkParse(b *testing.B) {
	for i := 0; i < b.N; i++ {
		p := &scan.Parser{Lexer: scan.Lex(testInput, LexMessage)}
		Parse(p)
	}
}
