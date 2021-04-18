package server

import (
	"fmt"
	"strings"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/server/cap"
)

type subcommand func(*Server, *client.Client, ...string)

var subs = map[string]subcommand{
	"LS":   LS,
	"LIST": capLIST,
	"REQ":  REQ,
	"END":  END,
}

// list capabilities that server supports
// TODO: support additional "LS 302" version param
func LS(s *Server, c *client.Client, params ...string) {
	// suspend registration if client has not yet registered
	if !c.Registered {
		c.RegSuspended = true
	}

	// TODO: generate all tags that server supports instead of hard-coding
	c.Write(fmt.Sprintf(":%s CAP %s LS :message-tags", s.listener.Addr(), clientId(c)))
}

// see what capabilities this client has active during this connection
func capLIST(s *Server, c *client.Client, params ...string) {
	enabledCaps := strings.Join(cap.StringSlice(c.Caps), " ")
	c.Write(fmt.Sprintf(":%s CAP %s LIST :%s", s.listener.Addr(), clientId(c), enabledCaps))
}

func REQ(s *Server, c *client.Client, params ...string) {
	// suspend registration if client has not yet registered
	if !c.Registered {
		c.RegSuspended = true
	}

	// TODO: missing params err code?
	if len(params) < 1 {
		s.numericReply(c, ERR_INVALIDCAPCMD, clientId(c), "CAP REQ")
	}

	// "The capability identifier set must be accepted as a whole, or
	// rejected entirely."
	// todo queues up the acceptance of the cap idents
	todo := []func(){}
	for _, v := range params {
		remove := false
		if v[0] == '-' {
			v = v[1:]
			remove = true
		}
		if cap := cap.Capability(v); cap.IsValid() {
			// "If a client requests a capability which is already enabled,
			// or tries to disable a capability which is not enabled, the
			// server MUST continue processing the REQ subcommand as though
			// handling this capability was successful."
			if (c.HasCap(cap) && !remove) || (!c.HasCap(cap) && remove) {
				continue
			}
			if remove {
				todo = append(todo, func() {
					for i := range c.Caps {
						if c.Caps[i] == cap {
							c.Caps = append(c.Caps[:i], c.Caps[i+1:]...)
						}
					}
				})
			} else {
				todo = append(todo, func() { c.Caps = append(c.Caps, cap) })
			}
		} else { // capability not recognized
			c.Write(fmt.Sprintf(":%s CAP %s NAK :%s", s.listener.Addr(), clientId(c), strings.Join(params, " ")))
			return
		}
	}

	// apply all changes
	for _, v := range todo {
		v()
	}
	c.Write(fmt.Sprintf(":%s CAP %s ACK :%s", s.listener.Addr(), clientId(c), strings.Join(params, " ")))
}

func END(s *Server, c *client.Client, params ...string) {
	// ignore if already registered
	if c.Registered {
		return
	}

	c.RegSuspended = false
	s.endRegistration(c)
}

// used for capability negotiation
func CAP(s *Server, c *client.Client, params ...string) {
	// no subcommand given
	if len(params) < 1 {
		s.numericReply(c, ERR_INVALIDCAPCMD, clientId(c), "CAP")
		return
	}

	subcom, ok := subs[params[0]]
	if !ok {
		s.numericReply(c, ERR_INVALIDCAPCMD, clientId(c), "CAP "+params[0])
		return
	}
	subcom(s, c, params[1:]...)
}

func clientId(c *client.Client) string {
	if c.Nick != "" {
		return c.Nick
	}
	return "*"
}
