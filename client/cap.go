package client

import (
	"github.com/mitchr/gossip/server/cap"
)

func (c *Client) ApplyCap(cap cap.Capability, remove bool) {
	// "If a client requests a capability which is already enabled,
	// or tries to disable a capability which is not enabled, the
	// server MUST continue processing the REQ subcommand as though
	// handling this capability was successful."
	if (c.Caps[cap] && !remove) || (!c.Caps[cap] && remove) {
		return
	}

	capHandlers[cap](c, remove)
	if remove {
		delete(c.Caps, cap)
	} else {
		c.Caps[cap] = true
	}
}

type capHandler func(*Client, bool)

var capHandlers = map[cap.Capability]capHandler{
	cap.MessageTags: messageTags,
}

func messageTags(c *Client, remove bool) {
	if !remove {
		c.maxMsgSize = 8191
	} else {
		c.maxMsgSize = 512
	}
}
