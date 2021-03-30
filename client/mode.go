package client

import (
	"github.com/mitchr/gossip/scan/mode"
)

type Mode uint

// Modes are represented as bit masks
const (
	None       Mode = 0
	Registered Mode = 1 << iota
	Invisible
	Wallops
	Away // TODO: should include this here? AWAY is weird
	Op
	LocalOp
)

var letter = map[rune]Mode{
	'i': Invisible,
	'o': Op,
	'O': LocalOp,
	'r': Registered,
	'w': Wallops,
}

func (m Mode) String() string {
	s := ""
	for k, v := range letter {
		if m&v == v {
			s += string(k)
		}
	}
	return s
}

func (c Client) Is(m Mode) bool {
	return c.Mode&m == m
}

// given a modeStr, apply the modes to c. If one of the runes does not
// correspond to a user mode, return it
func (c *Client) ApplyMode(b []byte) bool {
	m := mode.Parse(b)
	for _, v := range m {
		if mode, ok := letter[v.ModeChar]; ok {
			if v.Add {
				c.Mode |= mode
			} else {
				c.Mode &^= mode // this is hilarious
			}
		} else {
			return false
		}
	}
	return true
}
