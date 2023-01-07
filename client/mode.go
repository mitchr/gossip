package client

import (
	"github.com/mitchr/gossip/scan/mode"
)

type Mode uint8

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
	Bot
)

var letter = map[byte]Mode{
	'i': Invisible,
	'o': Op,
	'O': LocalOp,
	'r': Registered,
	'w': Wallops,
	'b': Bot,
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

func (c *Client) Is(m Mode) bool {
	c.modeLock.Lock()
	defer c.modeLock.Unlock()

	return c.Mode&m == m
}

func (c *Client) SetMode(m Mode) {
	c.modeLock.Lock()
	defer c.modeLock.Unlock()

	c.Mode |= m
}

func (c *Client) UnsetMode(m Mode) {
	c.modeLock.Lock()
	defer c.modeLock.Unlock()

	c.Mode &^= m
}

// given a modeStr, apply the modes to c. If one of the runes does not
// correspond to a user mode, return it
func (c *Client) ApplyMode(m mode.Mode) bool {
	mask, ok := letter[m.ModeChar]
	if ok {
		if m.Type == mode.Add {
			// a user cannot give themselves op this way; they must use OPER
			if mask == Op || mask == LocalOp {
				return false
			}
			c.SetMode(mask)
		} else {
			c.UnsetMode(mask)
		}
	}
	return ok
}
