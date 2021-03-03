package message

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		t []token
		m *Message
	}{
		{Lex([]byte(":dan!d@localhost PRIVMSG #chan :Hey!\r\n")), &Message{nil, "dan", "d", "localhost", "PRIVMSG", []string{"#chan"}, "Hey!"}},
		{Lex([]byte("NICK alice\r\n")), &Message{nil, "", "", "", "NICK", []string{"alice"}, ""}},
		{Lex([]byte(":dan!d@localhost QUIT :Quit: Bye for now!\r\n")), &Message{nil, "dan", "d", "localhost", "QUIT", nil, "Quit: Bye for now!"}},
		{Lex([]byte("USER alice 0 * :Alice Smith\r\n")), &Message{nil, "", "", "", "USER", []string{"alice", "0", "*"}, "Alice Smith"}},
		{nil, nil},
		// {lex([]byte("CAP * LS :multi-prefix sasl\r\n"))},
		// {lex([]byte("CAP REQ :sasl message-tags foo\r\n"))},
	}

	for _, v := range tests {
		if !reflect.DeepEqual(Parse(v.t), v.m) {
			t.Fatal("parse error", Parse(v.t), v.m)
		}
	}
}
