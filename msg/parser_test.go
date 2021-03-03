package msg

import (
	"reflect"
	"testing"
)

func TestParseMessage(t *testing.T) {
	tests := []struct {
		b []byte
		m *Message
	}{
		{[]byte(":dan!d@localhost PRIVMSG #chan :Hey!\r\n"), &Message{nil, "dan", "d", "localhost", "PRIVMSG", []string{"#chan"}, "Hey!"}},
		{[]byte("NICK alice\r\n"), &Message{nil, "", "", "", "NICK", []string{"alice"}, ""}},
		{[]byte(":dan!d@localhost QUIT :Quit: Bye for now!\r\n"), &Message{nil, "dan", "d", "localhost", "QUIT", nil, "Quit: Bye for now!"}},
		{[]byte("USER alice 0 * :Alice Smith\r\n"), &Message{nil, "", "", "", "USER", []string{"alice", "0", "*"}, "Alice Smith"}},
		{nil, nil},
		// {lex([]byte("CAP * LS :multi-prefix sasl\r\n"))},
		// {lex([]byte("CAP REQ :sasl message-tags foo\r\n"))},
	}

	for _, v := range tests {
		if !reflect.DeepEqual(ParseMessage(v.b), v.m) {
			t.Fatal("parse error", ParseMessage(v.b), v.m)
		}
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		i        string
		add, sub []rune
	}{
		{"+m", []rune{'m'}, nil},
		{"+mb", []rune{'m', 'b'}, nil},
		{"-i", nil, []rune{'i'}},
		{"+a-i", []rune{'a'}, []rune{'i'}},
		{"+a+b+c-de+f-g", []rune{'a', 'b', 'c', 'f'}, []rune{'d', 'e', 'g'}},
	}

	for _, v := range tests {
		a, s := ParseMode([]byte(v.i))
		if !reflect.DeepEqual(a, v.add) || !reflect.DeepEqual(s, v.sub) {
			t.Error(a, v.add, s, v.sub)
		}
	}
}
