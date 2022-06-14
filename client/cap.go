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
		c.msgSizeChange <- 4096 + 512
	}

	// request to remove, and client has no other caps that require message-tags
	if remove && !hasMessageTags {
		c.msgSizeChange <- 512
	}
}

var capsDependentOnMessageTags = [3]cap.Cap{cap.AccountTag, cap.MessageTags, cap.ServerTime}

func (c *Client) HasMessageTags() bool {
	for _, v := range capsDependentOnMessageTags {
		if c.Caps[v.Name] {
			return true
		}
	}
	return false
}
