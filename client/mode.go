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
	// away can stay here as long as it is never allowed to be set with
	// the MODE command; client must explicitly ask for this mode with AWAY
	Away
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

func (c *Client) Is(m Mode) bool { return c.Mode&m == m }

// given a modeStr, apply the modes to c. If one of the runes does not
// correspond to a user mode, return it
func (c *Client) ApplyMode(m mode.Mode) bool {
	if mask, ok := letter[m.ModeChar]; ok {
		if m.Type == mode.Add {
			// a user cannot give themselves op this way; they must use OPER
			if mask == Op || mask == LocalOp {
				return false
			}
			c.Mode |= mask
		} else {
			c.Mode &^= mask // this is hilarious
		}
	} else {
		return false
	}
	return true
}
