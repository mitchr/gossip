package channel

import (
	"sort"
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
	if (p == Operator || p == Halfop) && strings.ContainsRune(m.Prefix, rune(Founder)) {
		return true
	} else {
		return strings.ContainsRune(m.Prefix, rune(p))
	}
}

// Returns the highest prefix that the member has. If multiPrefix is
// true, returns all the modes that this member has in order of rank.
func (m Member) HighestPrefix(multiPrefix bool) string {
	modes := map[rune]uint8{
		rune(Founder):   4,
		rune(Protected): 3,
		rune(Operator):  2,
		rune(Halfop):    1,
		rune(Voice):     0,
	}
	prefix := []rune(m.Prefix)
	sort.Slice(prefix, func(i, j int) bool {
		return modes[prefix[i]] > modes[prefix[j]]
	})

	if multiPrefix {
		return string(prefix)
	}
	if len(prefix) > 0 {
		return string(prefix[0])
	}
	return ""
}

// Reconstruct this member's prefix string as a string of each prefix
// matched to its corresponding mode letter
func (m Member) ModeLetters() string {
	prefixToLetter := make(map[prefix]byte)
	for k, v := range memberLetter {
		prefixToLetter[v] = k
	}

	s := ""
	for _, l := range m.Prefix {
		letter, ok := prefixToLetter[prefix(l)]
		if ok {
			s += string(letter)
		}
	}
	return s
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
