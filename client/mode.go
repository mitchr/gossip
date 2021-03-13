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

// given a modeStr, apply the modes to c. If one of the runes does not
// correspond to a user mode, return it
func (c *Client) ApplyMode(b []byte) bool {
	add, sub := mode.Parse(b)
	for _, v := range add {
		if mode, ok := letter[v]; ok {
			c.Mode |= mode
		} else {
			return false
		}
	}

	for _, v := range sub {
		if mode, ok := letter[v]; ok {
			c.Mode &^= mode // this is hilarious
		} else {
			return false
		}
	}
	return true
}
