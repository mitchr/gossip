package client

import cap "github.com/mitchr/gossip/capability"

func (c *Client) ApplyCap(cap string, remove bool) {
	// "If a client requests a capability which is already enabled,
	// or tries to disable a capability which is not enabled, the
	// server MUST continue processing the REQ subcommand as though
	// handling this capability was successful."
	if (c.Caps[cap] && !remove) || (!c.Caps[cap] && remove) {
		return
	}

	handler := capHandlers[cap]
	if handler != nil {
		handler(c, remove)
	}
	if remove {
		delete(c.Caps, cap)
	} else {
		c.Caps[cap] = true
	}
}

type capHandler func(*Client, bool)

var capHandlers = map[string]capHandler{
	cap.AccountTag.Name:  messageTags,
	cap.MessageTags.Name: messageTags,
	cap.ServerTime.Name:  messageTags,
}

func messageTags(c *Client, remove bool) {
	hasMessageTags := c.HasMessageTags()

	if !remove && !hasMessageTags {
		newBuf := make([]byte, 4096+512)
		copy(newBuf, c.msgBuf)
		c.msgBuf = newBuf
	}

	// request to remove, and client has no other caps that require message-tags
	if remove && !hasMessageTags {
		newBuf := make([]byte, 512)
		copy(newBuf, c.msgBuf)
		c.msgBuf = newBuf
	}
}

func (c *Client) HasMessageTags() bool { return c.Caps[cap.MessageTags.Name] }
