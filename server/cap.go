package server

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"

	cap "github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

type subcommand func(*Server, *client.Client, ...string) msg.Msg

var subs = map[string]subcommand{
	"LS":   LS,
	"LIST": capLIST,
	"REQ":  REQ,
	"END":  END,
}

// list capabilities that server supports
// TODO (only for CAP302 clients): when server capabilties take up too
// much message space, split up into multiple responses like
//
//	CAP * LS * :
//	CAP * LS :
func LS(s *Server, c *client.Client, params ...string) msg.Msg {
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

	return msg.New(nil, s.Name, "", "", "CAP", []string{c.Id(), "LS", s.capString(version >= 302)}, true)
}

// see what capabilities this client has active during this connection
func capLIST(s *Server, c *client.Client, params ...string) msg.Msg {
	return msg.New(nil, s.Name, "", "", "CAP", []string{c.Id(), "LIST", c.CapsSet()}, true)
}

func REQ(s *Server, c *client.Client, params ...string) msg.Msg {
	// suspend registration if client has not yet registered
	if !c.Is(client.Registered) {
		c.RegSuspended = true
	}

	// if a client requests multiple caps it will be in the form ':cap1
	// cap2 cap3' which the message parser will treat as one entire
	// parameter. we have to split it ourselves here
	if len(params) > 0 {
		params = strings.Split(params[0], " ")
	}

	// "The capability identifier set must be accepted as a whole, or
	// rejected entirely."
	// todo queues up the acceptance of the cap idents
	todo := make([]struct {
		cap    string
		remove bool
	}, len(params))
	for i, v := range params {
		remove := false
		if v[0] == '-' {
			v = v[1:]
			remove = true
		}
		if s.hasCap(v) {
			todo[i].cap = v
			todo[i].remove = remove
		} else { // capability not recognized
			return msg.New(nil, s.Name, "", "", "CAP", []string{c.Id(), "NAK", strings.Join(params, " ")}, true)
		}
	}

	// apply all changes
	for _, v := range todo {
		c.ApplyCap(v.cap, v.remove)
	}
	return msg.New(nil, s.Name, "", "", "CAP", []string{c.Id(), "ACK", strings.Join(params, " ")}, true)
}

func END(s *Server, c *client.Client, params ...string) msg.Msg {
	// ignore if already registered
	if c.Is(client.Registered) {
		return nil
	}

	c.RegSuspended = false
	return s.endRegistration(c)
}

// used for capability negotiation
func CAP(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	// no subcommand given
	if len(m.Params) < 1 {
		return prepMessage(ERR_INVALIDCAPCMD, s.Name, c.Id(), "")
	}

	subcom, ok := subs[strings.ToUpper(m.Params[0])]
	if !ok {
		return prepMessage(ERR_INVALIDCAPCMD, s.Name, c.Id(), m.Params[0])
	}
	return subcom(s, c, m.Params[1:]...)
}

func TAGMSG(s *Server, c *client.Client, m *msg.Message) msg.Msg { return s.communicate(m, c) }

func (s *Server) capString(cap302Enabled bool) string {
	caps := ""
	for i, v := range s.supportedCaps {
		caps += v.Name
		if cap302Enabled && len(v.Value) > 0 {
			if v == cap.STS {
				caps += "=" + s.getSTSValue()
			} else {
				caps += "=" + v.Value
			}
		}
		if i != len(s.supportedCaps)-1 {
			caps += " "
		}
	}
	return caps
}

func (s *Server) getSTSValue() string {
	// calculate TLS certificate expiration duration for sts value
	var duration time.Duration
	if s.TLS.STS.Duration != 0 {
		duration = s.TLS.STS.Duration
	} else {
		// use time until certificate expires
		cert, _ := x509.ParseCertificate(s.TLS.Config.Certificates[0].Certificate[0])
		duration = time.Until(cert.NotAfter)
	}

	val := fmt.Sprintf(cap.STS.Value, s.Config.TLS.STS.Port, duration.Seconds())
	if s.Config.TLS.STS.Preload {
		val += ",preload"
	}

	return val
}
