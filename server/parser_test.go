package server

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		t []token
		m *message
	}{
		{lex([]byte(":dan!d@localhost PRIVMSG #chan :Hey!\r\n")), &message{nil, "dan", "d", "localhost", "PRIVMSG", []string{"#chan"}, "Hey!"}},
		{lex([]byte("NICK alice\r\n")), &message{nil, "", "", "", "NICK", []string{"alice"}, ""}},
		{lex([]byte("USER alice 0 * :Alice Smith\r\n")), &message{nil, "", "", "", "USER", []string{"alice", "0", "*"}, "Alice Smith"}},
		// {lex([]byte("CAP * LS :multi-prefix sasl\r\n"))},
		// {lex([]byte("CAP REQ :sasl message-tags foo\r\n"))},
	}

	for _, v := range tests {
		if !reflect.DeepEqual(parse(v.t), v.m) {
			t.Fatal("parse error", parse(v.t), v.m)
		}
	}
}
