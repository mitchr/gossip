package client

import (
	"github.com/mitchr/gossip/cap"
)

func (c *Client) ApplyCap(cap string, remove bool) {
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

var capHandlers = map[string]capHandler{
	cap.CapNotify.Name:   doNothing,
	cap.EchoMessage.Name: doNothing,
	cap.MessageTags.Name: messageTags,
	cap.SASL.Name:        doNothing,
	cap.ServerTime.Name:  doNothing,
}

// used to capabilities that are just basically advertisements, like cap-notify
func doNothing(c *Client, r bool) {}

func messageTags(c *Client, remove bool) {
	c.capLock.Lock()
	defer c.capLock.Unlock()

	if !remove {
		// space for tags and message
		c.maxMsgSize = 8191 + 512
	} else {
		c.maxMsgSize = 512
	}
}
