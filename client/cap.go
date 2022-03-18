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

	capHandlers[cap](c, remove)
	if remove {
		delete(c.Caps, cap)
	} else {
		c.Caps[cap] = true
	}
}

type capHandler func(*Client, bool)

var capHandlers = map[string]capHandler{
	cap.AwayNotify.Name:  doNothing,
	cap.CapNotify.Name:   doNothing,
	cap.EchoMessage.Name: doNothing,
	cap.MessageTags.Name: messageTags,
	cap.SASL.Name:        doNothing,
	cap.ServerTime.Name:  implictlyRequireMessageTags, // server-time implicitly requires message-tags
	cap.Setname.Name:     doNothing,
}

// used to capabilities that are just basically advertisements, like cap-notify
func doNothing(*Client, bool) {}

func messageTags(c *Client, remove bool) {
	if !remove {
		// space for tags and message
		c.msgSizeChange <- 8191 + 512
	} else {
		c.msgSizeChange <- 512
	}
}

func implictlyRequireMessageTags(c *Client, remove bool) {
	messageTags(c, remove)
	if remove {
		delete(c.Caps, cap.MessageTags.Name)
	} else {
		c.Caps[cap.MessageTags.Name] = true
	}
}
