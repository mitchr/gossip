package server

import (
	"fmt"

	"github.com/mitchr/gossip/client"
)

type subcommand func(*Server, *client.Client, ...string)

var subs = map[string]subcommand{
	"LS":  LS,
	"END": END,
}

func LS(s *Server, c *client.Client, params ...string) {
	// suspend registration if client has not yet registered
	if !c.Registered {
		c.RegSuspended = true
	}

	// TODO: support additional "LS 302" version param

	c.Write(fmt.Sprintf(":%s CAP * LS :\r\n", s.listener.Addr()))
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
