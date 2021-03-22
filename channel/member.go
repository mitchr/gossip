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
	Mode string
}

func (m Member) Is(p prefix) bool {
	return strings.ContainsRune(m.Mode, rune(p))
}

func (m *Member) ApplyMode(mode mode.Mode) bool {
	r, ok := memberLetter[mode.ModeChar]
	if ok {
		if mode.Add {
			m.Mode += string(r)
		} else {
			m.Mode = strings.Replace(m.Mode, string(r), "", -1)
		}
	}
	return ok
}
