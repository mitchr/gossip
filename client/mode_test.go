package client

import (
	"testing"

	"github.com/mitchr/gossip/scan/mode"
)

func TestModeApplication(t *testing.T) {
	tests := []struct {
		in   mode.Mode
		out  bool
		mask Mode
	}{
		{mode.Mode{ModeChar: 'i', Type: mode.Add}, true, Invisible},
		{mode.Mode{ModeChar: 'r', Type: mode.Add}, true, Registered},
		{mode.Mode{ModeChar: 'a', Type: mode.Add}, false, 0}, //nonexistant modes
	}

	for _, v := range tests {
		c := &Client{}
		result := c.ApplyMode(v.in)
		if result != v.out {
			t.Error(result, v.out)
		}
		if c.Mode != v.mask {
			t.Error(uint(c.Mode), uint(v.mask))
		}
	}
}
