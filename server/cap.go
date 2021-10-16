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
		c.ApplyCap(cap.CapNotify, false)

		if s.TLS.STSEnabled {
			s.updateSTSValue()
		}
	}

	caps := make([]string, len(cap.SupportedCaps))
	i := 0
	for _, v := range cap.SupportedCaps {
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
	todo := make([]func(), len(params))
	for i, v := range params {
		remove := false
		if v[0] == '-' {
			v = v[1:]
			remove = true
		}
		if cap, ok := cap.SupportedCaps[v]; ok {
			todo[i] = func() { c.ApplyCap(cap, remove) }
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

// calculate TLS certificate expiration duration for sts value
func (s *Server) updateSTSValue() {
	var port string
	if s.TLS.STSPort != "" {
		port = s.TLS.STSPort
	} else {
		// trim ':' from port
		port = s.TLS.Port[1:]
	}

	var duration time.Duration
	if s.TLS.STSDuration != 0 {
		duration = s.TLS.STSDuration
	} else {
		// use time until certificate expires
		cert, _ := x509.ParseCertificate(s.TLS.Config.Certificates[0].Certificate[0])
		duration = time.Until(cert.NotAfter)
	}

	stsCopy := cap.SupportedCaps[cap.STS.Name]
	stsCopy.Value = fmt.Sprintf(cap.STS.Value, port, duration.Seconds())
	if s.Config.TLS.STSPreload {
		stsCopy.Value += ",preload"
	}
	cap.SupportedCaps[cap.STS.Name] = stsCopy
}
