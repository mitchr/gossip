package server

import (
	"fmt"
	"strings"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
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
	if !c.Is(client.Registered) {
		c.RegSuspended = true
	}

	// TODO: generate all tags that server supports instead of hard-coding
	c.Write(fmt.Sprintf(":%s CAP %s LS :message-tags", s.Name, clientId(c)))
}

// see what capabilities this client has active during this connection
func capLIST(s *Server, c *client.Client, params ...string) {
	c.Write(fmt.Sprintf(":%s CAP %s LIST :%s", s.Name, clientId(c), c.CapsSet()))
}

func REQ(s *Server, c *client.Client, params ...string) {
	// suspend registration if client has not yet registered
	if !c.Is(client.Registered) {
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
			if (c.Caps[cap] && !remove) || (!c.Caps[cap] && remove) {
				continue
			}
			if remove {
				todo = append(todo, func() { delete(c.Caps, cap) })
			} else {
				todo = append(todo, func() { c.Caps[cap] = true })
			}
		} else { // capability not recognized
			c.Write(fmt.Sprintf(":%s CAP %s NAK :%s", s.Name, clientId(c), strings.Join(params, " ")))
			return
		}
	}

	// apply all changes
	for _, v := range todo {
		v()
	}
	c.Write(fmt.Sprintf(":%s CAP %s ACK :%s", s.Name, clientId(c), strings.Join(params, " ")))
}

func END(s *Server, c *client.Client, params ...string) {
	// ignore if already registered
	if c.Is(client.Registered) {
		return
	}

	c.RegSuspended = false
	s.endRegistration(c)
}

// used for capability negotiation
func CAP(s *Server, c *client.Client, m *msg.Message) {
	// no subcommand given
	if len(m.Params) < 1 {
		s.numericReply(c, ERR_INVALIDCAPCMD, clientId(c), "CAP")
		return
	}

	subcom, ok := subs[m.Params[0]]
	if !ok {
		s.numericReply(c, ERR_INVALIDCAPCMD, clientId(c), "CAP "+m.Params[0])
		return
	}
	subcom(s, c, m.Params[1:]...)
}

func clientId(c *client.Client) string {
	if c.Nick != "" {
		return c.Nick
	}
	return "*"
}
