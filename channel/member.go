package channel

import (
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/mode"
)

// Member is a Client that belongs to a channel. Members, unlike
// Clients, have the capability to be given a mode/prefix.
type Member struct {
	*client.Client
	Prefix prefix
}

func (m Member) Is(p prefix) bool {
	if (p == Operator || p == Halfop) && m.Prefix&Founder == Founder {
		return true
	} else {
		return m.Prefix&p == p
	}
}

// Returns the highest prefix that the member has. If multiPrefix is
// true, returns all the modes that this member has in order of rank.
func (m Member) HighestPrefix(multiPrefix bool) string {
	if m.Prefix == 0 {
		return ""
	} else if multiPrefix {
		return m.Prefix.String()
	} else {
		return string(m.Prefix.String()[0])
	}
}

// Reconstruct this member's prefix string as a string of each prefix
// matched to its corresponding mode letter
func (m Member) ModeLetters() string { return m.Prefix.modeLetters() }

func (c *Member) ApplyMode(m mode.Mode) bool {
	r, ok := memberLetter[m.ModeChar]
	if ok {
		if m.Type == mode.Add {
			c.Prefix |= r
		} else {
			c.Prefix &^= r
		}
	}
	return ok
}
