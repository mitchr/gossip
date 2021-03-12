package channel

import (
	"strings"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/msg"
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
	add, sub := msg.ParseMode(b)
	for _, v := range add {
		if p, ok := memberLetter[v]; ok {
			m.prefixes += string(p)
		} else {
			return false
		}
	}

	for _, v := range sub {
		if p, ok := memberLetter[v]; ok {
			m.prefixes = strings.Replace(m.prefixes, string(p), "", -1)
		} else {
			return false
		}
	}
	return true
}
