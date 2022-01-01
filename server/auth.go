package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/mitchr/gossip/cap"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/sasl"
	"github.com/mitchr/gossip/sasl/external"
	"github.com/mitchr/gossip/sasl/plain"
	"github.com/mitchr/gossip/sasl/scram"
	"github.com/mitchr/gossip/scan/msg"
)

func AUTHENTICATE(s *Server, c *client.Client, m *msg.Message) {
	// client must have requested the SASL capability, and has not yet registered
	if !c.Caps[cap.SASL.Name] || c.Is(client.Registered) {
		// TODO: what error to give?
		s.writeReply(c, c.Id(), ERR_SASLFAIL)
		return
	}

	// "If the client attempts to issue the AUTHENTICATE command after
	// already authenticating successfully, the server MUST reject it
	// with a 907 numeric"
	if c.IsAuthenticated {
		s.writeReply(c, c.Id(), ERR_SASLALREADY)
		return
	}

	// "If the client completes registration (with CAP END, NICK, USER and
	// any other necessary messages) while the SASL authentication is
	// still in progress, the server SHOULD abort it and send a 906
	// numeric, then register the client without authentication"
	if c.Is(client.Registered) && c.SASLMech != nil && !c.IsAuthenticated {
		c.SASLMech = nil
		s.writeReply(c, c.Id(), ERR_SASLABORTED)
		return
	}

	if len(m.Params) == 0 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "AUTHENTICATE")
		return
	}

	if m.Params[0] == "*" {
		c.SASLMech = nil
		s.writeReply(c, c.Id(), ERR_SASLABORTED)
		return
	}

	// this client has no mechanism yet
	if c.SASLMech == nil {
		switch m.Params[0] {
		case "PLAIN":
			c.SASLMech = plain.NewPlain(s.db)
		case "EXTERNAL":
			c.SASLMech = external.NewExternal(s.db, c)
		case "SCRAM":
			c.SASLMech = scram.NewScram(s.db, sha256.New)
		default:
			s.writeReply(c, c.Id(), RPL_SASLMECHS, cap.SASL.Value)
			return
		}

		// TODO: all currently supported SASL mechanisms are client-first,
		// so we can be assured that the server should be sending a blank
		// challenge here. In the future if more mechanisms are added, this
		// will have to be reevaluated
		fmt.Fprintf(c, ":%s AUTHENTICATE +", s.Name)
		return
	}

	// TODO: this kind of request can have a continuation if the initial
	// request byte count is over 400, so we should check to see if we
	// have a situation like this and append the messages together before
	// decoding
	// *("AUTHENTICATE" SP 400BASE64 CRLF) "AUTHENTICATE" SP (1*399BASE64 / "+") CRLF
	decodedResp, err := base64.StdEncoding.DecodeString(m.Params[0])
	if err != nil {
		// TODO: is this an acceptable response?
		s.writeReply(c, c.Id(), ERR_SASLFAIL)
	}

	challenge, err := c.SASLMech.Next(decodedResp)
	if err != nil {
		if err == sasl.ErrDone {
			c.IsAuthenticated = true
			// TODO: what are <account> and <user>?
			s.writeReply(c, c.Id(), RPL_LOGGEDIN, c, c.Id(), c.Id())
			s.writeReply(c, c.Id(), RPL_SASLSUCCESS)
		}
		s.writeReply(c, c.Id(), ERR_SASLFAIL)
		return
	}

	encodedChallenge := base64.StdEncoding.EncodeToString(challenge)
	s.writeReply(c, c.Id(), "AUTHENTICATE %s", encodedChallenge)
}

// REGISTER is nonstandard
// for now, username is assumed to be the same as the current client's nick
// REGISTER PASS <pass>
// REGISTER CERT
func REGISTER(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) == 0 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "REGISTER")
		return
	}

	switch m.Params[0] {
	case "PASS":
		if len(m.Params) < 2 {
			// TODO; fail because no password argument
			s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "REGISTER PASS")
			return
		}
		pass := m.Params[1]

		plainCred := plain.NewCredential(c.Id(), pass)
		s.db.Exec("INSERT INTO sasl_plain VALUES(?, ?)", plainCred.Username, plainCred.Pass)

		salt := make([]byte, 16)
		rand.Read(salt)
		scramCred := scram.NewCredential(sha256.New, c.Id(), pass, base64.StdEncoding.EncodeToString(salt), 4096)
		s.db.Exec("INSERT INTO sasl_scram VALUES(?, ?, ?, ?, ?)", scramCred.Username, scramCred.ServerKey, scramCred.StoredKey, scramCred.Salt, scramCred.Iteration)

	case "CERT":
		cred, err := external.NewCredential(c.Id(), c.Conn)
		if err != nil {
			// TODO: fail registration
		}
		s.db.Exec("INSERT INTO sasl_exec VALUES(?, ?)", cred.Username, cred.Cert)
	}

	fmt.Fprintf(c, "NOTICE Registered")
}
