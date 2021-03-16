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

func (m *Member) ApplyMode(mode mode.Mode) bool {
	if r, ok := memberLetter[mode.ModeChar]; ok {
		if mode.Add {
			m.prefixes += string(r)
		} else {
			m.prefixes = strings.Replace(m.prefixes, string(r), "", -1)
		}
	} else {
		return false
	}
	return true
}
