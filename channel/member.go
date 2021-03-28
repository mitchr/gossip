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

func (m *Member) ApplyMode(mode mode.Mode) bool {
	r, ok := memberLetter[mode.ModeChar]
	if ok {
		if mode.Add {
			m.Prefix += string(r)
		} else {
			m.Prefix = strings.Replace(m.Prefix, string(r), "", -1)
		}
	}
	return ok
}
