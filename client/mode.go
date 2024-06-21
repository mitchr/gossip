package client

import (
	"sync/atomic"

	"github.com/mitchr/gossip/scan/mode"
)

type Mode uint32

// Modes are represented as bit masks
const (
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
	switch m {
	case Registered:
		return "r"
	case Invisible:
		return "i"
	case Wallops:
		return "w"
	case Op:
		return "o"
	case LocalOp:
		return "O"
	case Bot:
		return "b"
	}

	s := ""
	for i := Registered; i < Bot; i <<= 1 {
		if m&i == 0 {
			s += i.String()
		}
	}
	return s
}

func (c *Client) Is(m Mode) bool {
	mode := Mode(atomic.LoadUint32((*uint32)(&c.Mode)))
	return mode&m == m
}

func (c *Client) SetMode(m Mode) {
	for {
		mode := atomic.LoadUint32((*uint32)(&c.Mode))
		if atomic.CompareAndSwapUint32((*uint32)(&c.Mode), mode, mode|uint32(m)) {
			return
		}
	}
}

func (c *Client) UnsetMode(m Mode) {
	for {
		mode := atomic.LoadUint32((*uint32)(&c.Mode))
		if atomic.CompareAndSwapUint32((*uint32)(&c.Mode), mode, mode&^uint32(m)) {
			return
		}
	}
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
