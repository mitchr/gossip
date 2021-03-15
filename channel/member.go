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
	prefixes string
}

func NewMember(c *client.Client, p string) *Member {
	return &Member{c, p}
}

func (m *Member) ApplyMode(b []byte) bool {
	modes := mode.Parse(b)
	for _, v := range modes {
		if r, ok := memberLetter[v.ModeChar]; ok {
			if v.Add {
				m.prefixes += string(r)
			} else {
				m.prefixes = strings.Replace(m.prefixes, string(r), "", -1)
			}
		} else {
			return false
		}
	}
	return true
}
