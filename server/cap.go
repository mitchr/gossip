package server

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"

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

	if c.SupportsCapVersion(302) {
		// CAP LS 302 implicitly adds 'cap-notify' to capabilities
		c.ApplyCap(cap.CapNotify.Name, false)
	}

	s.writeReply(c, c.Id(), ":%s CAP %s LS :%s", s.capString(version >= 302))
}

// see what capabilities this client has active during this connection
func capLIST(s *Server, c *client.Client, params ...string) {
	s.writeReply(c, c.Id(), ":%s CAP %s LIST :%s", c.CapsSet())
}

func REQ(s *Server, c *client.Client, params ...string) {
	// suspend registration if client has not yet registered
	if !c.Is(client.Registered) {
		c.RegSuspended = true
	}

	// "The capability identifier set must be accepted as a whole, or
	// rejected entirely."
	// todo queues up the acceptance of the cap idents
	todo := make([]func(), len(params))
	for i, v := range params {
		remove := false
		if v[0] == '-' {
			v = v[1:]
			remove = true
		}
		if cap.IsRecognized(v) {
			todo[i] = func() { c.ApplyCap(v, remove) }
		} else { // capability not recognized
			s.writeReply(c, c.Id(), ":%s CAP %s NAK :%s", strings.Join(params, " "))
			return
		}
	}

	// apply all changes
	for _, v := range todo {
		v()
	}
	s.writeReply(c, c.Id(), ":%s CAP %s ACK :%s", strings.Join(params, " "))
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
		s.writeReply(c, c.Id(), ERR_INVALIDCAPCMD, "CAP")
		return
	}

	subcom, ok := subs[strings.ToUpper(m.Params[0])]
	if !ok {
		s.writeReply(c, c.Id(), ERR_INVALIDCAPCMD, "CAP "+m.Params[0])
		return
	}
	subcom(s, c, m.Params[1:]...)
}

func TAGMSG(s *Server, c *client.Client, m *msg.Message) { s.communicate(m, c) }

func (s *Server) capString(cap302Enabled bool) string {
	caps := make([]string, len(s.supportedCaps))
	for i, v := range s.supportedCaps {
		caps[i] = v.Name
		if cap302Enabled && len(v.Value) > 0 {
			if v == cap.STS {
				caps[i] += "=" + s.getSTSValue()
			} else {
				caps[i] += "=" + v.Value
			}
		}
	}
	return strings.Join(caps, " ")
}

func (s *Server) getSTSValue() string {
	// calculate TLS certificate expiration duration for sts value
	var duration time.Duration
	if s.TLS.STSDuration != 0 {
		duration = s.TLS.STSDuration
	} else {
		// use time until certificate expires
		cert, _ := x509.ParseCertificate(s.TLS.Config.Certificates[0].Certificate[0])
		duration = time.Until(cert.NotAfter)
	}

	val := fmt.Sprintf(cap.STS.Value, s.Config.TLS.STSPort, duration.Seconds())
	if s.Config.TLS.STSPreload {
		val += ",preload"
	}

	return val
}
