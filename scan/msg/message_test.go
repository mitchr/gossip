package msg

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/mitchr/gossip/scan"
)

func TestLexParams(t *testing.T) {
	tests := map[string][]scan.Token{
		" CAP * LIST\r\n":              {{space, " "}, {nospcrlfcl, "CAP"}, {space, " "}, {nospcrlfcl, "*"}, {space, " "}, {nospcrlfcl, "LIST"}, {crlf, "\r\n"}},
		" * LS :multi-prefix sasl\r\n": {{space, " "}, {nospcrlfcl, "*"}, {space, " "}, {nospcrlfcl, "LS"}, {space, " "}, {colon, ":"}, {nospcrlfcl, "multi-prefix"}, {space, " "}, {nospcrlfcl, "sasl"}, {crlf, "\r\n"}},

		// " REQ :sasl message-tags foo": {{middle, "REQ"}, {trailing, "sasl message-tags foo"}},
		// " #chan :Hey!":                {{middle, "#chan"}, {trailing, "Hey!"}},
		// " #chan Hey!":                 {{middle, "#chan"}, {middle, "Hey!"}},
		// "        #chan       Hey!":    {{middle, "#chan"}, {middle, "Hey!"}}, // variation with extra whitespace
	}

	for k, v := range tests {
		t.Run(k, func(t *testing.T) {
			if !reflect.DeepEqual(scan.Lex([]byte(k), lexMessage), v) {
				fmt.Println(scan.Lex([]byte(k), lexMessage))
				t.Errorf("Failed to lex %s\n", k)
			}
		})
	}
}

func TestParseMessage(t *testing.T) {
	tests := []struct {
		b []byte
		m *Message
	}{
		{[]byte(":dan!d@localhost PRIVMSG #chan :Hey!\r\n"), &Message{nil, "dan", "d", "localhost", "PRIVMSG", []string{"#chan"}, "Hey!", true}},
		{[]byte("NICK alice\r\n"), &Message{nil, "", "", "", "NICK", []string{"alice"}, "", false}},
		{[]byte(":dan!d@localhost QUIT :Quit: Bye for now!\r\n"), &Message{nil, "dan", "d", "localhost", "QUIT", nil, "Quit: Bye for now!", true}},
		{[]byte("USER alice 0 * :Alice Smith\r\n"), &Message{nil, "", "", "", "USER", []string{"alice", "0", "*"}, "Alice Smith", true}},
		{nil, nil},
		// {lex([]byte("CAP * LS :multi-prefix sasl\r\n"))},
		// {lex([]byte("CAP REQ :sasl message-tags foo\r\n"))},
	}

	for _, v := range tests {
		if !reflect.DeepEqual(Parse(v.b), v.m) {
			t.Fatal("parse error", Parse(v.b), v.m)
		}
	}
}
