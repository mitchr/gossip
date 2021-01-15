package server

import (
	"testing"
)

func TestParseSource(t *testing.T) {
	tests := []struct {
		input, nick, user, host string
	}{
		{":amy!a@foo.example.com", "amy", "a", "foo.example.com"},
		{":dan!d@localhost", "dan", "d", "localhost"},
		{":foo.example.com", "", "", "foo.example.com"},
		{":noHost", "", "", "noHost"},
	}

	for _, v := range tests {
		nick, user, host := parseSource(v.input)
		if nick != v.nick || user != v.user || host != v.host {
			t.Error(v)
		}
	}
}
