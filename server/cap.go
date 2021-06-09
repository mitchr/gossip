package server

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mitchr/gossip/cap"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

type subcommand func(*Server, *client.Client, ...string)

var subs = map[string]subcommand{
	"LS":   LS,
	"LIST": capLIST,
	"REQ":  REQ,
	"END":  END,
}

// list capabilities that server supports
// TODO (only for CAP302 clients): when server capabilties take up too
// much message space, split up into multiple responses like
// 	CAP * LS * :
// 	CAP * LS :
func LS(s *Server, c *client.Client, params ...string) {
	// suspend registration if client has not yet registered
	if !c.Is(client.Registered) {
		c.RegSuspended = true
	}

	version := 0
	if len(params) > 0 {
		version, _ = strconv.Atoi(params[0])
	}
	// store largest cap version
	if version > c.CapVersion {
		c.CapVersion = version
	}
	// CAP LS 302 implicitly adds 'cap-notify' to capabilities
	if c.SupportsCapVersion(302) {
		c.ApplyCap(cap.CapNotify, false)
	}

	caps := make([]string, len(cap.Caps))
	i := 0
	for _, v := range cap.Caps {
		caps[i] = v.Name
		if version >= 302 && len(v.Value) > 0 {
			caps[i] += "=" + v.Value
		}
		i++
	}
	fmt.Fprintf(c, ":%s CAP %s LS :%s", s.Name, c.Id(), strings.Join(caps, " "))
}

// see what capabilities this client has active during this connection
func capLIST(s *Server, c *client.Client, params ...string) {
	fmt.Fprintf(c, ":%s CAP %s LIST :%s", s.Name, c.Id(), c.CapsSet())
}

func REQ(s *Server, c *client.Client, params ...string) {
	// suspend registration if client has not yet registered
	if !c.Is(client.Registered) {
		c.RegSuspended = true
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
		if cap, ok := cap.Caps[v]; ok {
			todo = append(todo, func() { c.ApplyCap(cap, remove) })
		} else { // capability not recognized
			fmt.Fprintf(c, ":%s CAP %s NAK :%s", s.Name, c.Id(), strings.Join(params, " "))
			return
		}
	}

	// apply all changes
	for _, v := range todo {
		v()
	}
	fmt.Fprintf(c, ":%s CAP %s ACK :%s", s.Name, c.Id(), strings.Join(params, " "))
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
		s.numericReply(c, ERR_INVALIDCAPCMD, c.Id(), "CAP")
		return
	}

	subcom, ok := subs[strings.ToUpper(m.Params[0])]
	if !ok {
		s.numericReply(c, ERR_INVALIDCAPCMD, c.Id(), "CAP "+m.Params[0])
		return
	}
	subcom(s, c, m.Params[1:]...)
}

func TAGMSG(s *Server, c *client.Client, m *msg.Message) { s.communicate(m, c) }
