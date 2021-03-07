package client

import (
	"testing"
)

func TestModeApplication(t *testing.T) {
	tests := []struct {
		in   string
		mode Mode
	}{
		{"+i", Invisible},
		{"+ir", Invisible | Registered},
		{"+i-i", None},
		{"+abcdefg", None}, //nonexistant modes
		{"-abcdefg", None}, //nonexistant modes
	}

	for _, v := range tests {
		c := &Client{}
		c.ApplyMode([]byte(v.in))
		if c.Mode != v.mode {
			t.Error(uint(c.Mode), uint(v.mode))
		}
	}
}
