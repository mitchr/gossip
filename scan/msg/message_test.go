package msg

import (
	"fmt"
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
			if !reflect.DeepEqual(scan.Lex([]byte(k), lexMessage), v) {
				fmt.Println(scan.Lex([]byte(k), lexMessage))
				t.Errorf("Failed to lex %s\n", k)
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
				middle:      []string{"#chan"},
				trailing:    "Hey!",
				trailingSet: true,
			},
		},
		{"NICK alice\r\n", &Message{Command: "NICK", middle: []string{"alice"}}},
		{":dan!d@123.456.789 QUIT :Quit: Bye for now!\r\n",
			&Message{
				nick:        "dan",
				user:        "d",
				host:        "123.456.789",
				Command:     "QUIT",
				trailing:    "Quit: Bye for now!",
				trailingSet: true,
			},
		},
		{"USER alice 0 * :Alice Smith\r\n",
			&Message{
				Command:     "USER",
				middle:      []string{"alice", "0", "*"},
				trailing:    "Alice Smith",
				trailingSet: true,
			},
		},
		{"", nil},
		// {lex([]byte("CAP * LS :multi-prefix sasl\r\n"))},
		// {lex([]byte("CAP REQ :sasl message-tags foo\r\n"))},
	}

	for _, v := range tests {
		t.Run(v.s, func(t *testing.T) {
			if !reflect.DeepEqual(Parse([]byte(v.s)), v.m) {
				t.Fatal("parse error", Parse([]byte(v.s)), v.m)
			}
		})
	}
}
