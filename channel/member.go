package channel

import "github.com/mitchr/gossip/client"

type Prefix rune

const (
	Founder   Prefix = '~'
	Protected Prefix = '&'
	Operator  Prefix = '@'
	Halfop    Prefix = '%'
	Voice     Prefix = '+'
)

// Member is a Client that belongs to a channel. Members, unlike
// Clients, have the capability to be given a mode/prefix.
type Member struct {
	*client.Client
	Prefixes string
}

func NewMember(c *client.Client, p string) *Member {
	return &Member{c, p}
}
