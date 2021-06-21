package channel

import (
	"strings"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/mode"
)

// Member is a Client that belongs to a channel. Members, unlike
// Clients, have the capability to be given a mode/prefix.
type Member struct {
	*client.Client
	Prefix string
}

func (m Member) Is(p prefix) bool {
	// a founder satisfies all prefixes
	if strings.ContainsRune(m.Prefix, rune(Founder)) {
		return true
	} else {
		return strings.ContainsRune(m.Prefix, rune(p))
	}
}

// Returns the highest prefix that the member has. If this member does
// not have any prefix, return -1.
func (m Member) HighestPrefix() prefix {
	modes := []prefix{Founder, Protected, Operator, Halfop, Voice}
	for _, v := range modes {
		if strings.ContainsRune(m.Prefix, rune(v)) {
			return v
		}
	}
	return -1
}

func (c *Member) ApplyMode(m mode.Mode) bool {
	r, ok := memberLetter[m.ModeChar]
	if ok {
		if m.Type == mode.Add {
			c.Prefix += string(r)
		} else {
			c.Prefix = strings.Replace(c.Prefix, string(r), "", -1)
		}
	}
	return ok
}
