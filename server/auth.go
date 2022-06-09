package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	cap "github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/sasl"
	"github.com/mitchr/gossip/sasl/external"
	"github.com/mitchr/gossip/sasl/plain"
	"github.com/mitchr/gossip/sasl/scram"
	"github.com/mitchr/gossip/scan/msg"
)

func AUTHENTICATE(s *Server, c *client.Client, m *msg.Message) {
	_, saslNone := c.SASLMech.(sasl.None)
	// "If the client completes registration (with CAP END, NICK, USER and
	// any other necessary messages) while the SASL authentication is
	// still in progress, the server SHOULD abort it and send a 906
	// numeric, then register the client without authentication"
	if c.Is(client.Registered) && !saslNone && !c.IsAuthenticated {
		c.SASLMech = nil
		s.writeReply(c, c.Id(), ERR_SASLABORTED)
		return
	}

	// client must have requested the SASL capability, and has not yet registered
	if !c.Caps[cap.SASL.Name] || c.Is(client.Registered) {
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
	if saslNone {
		switch m.Params[0] {
		case "PLAIN":
			c.SASLMech = plain.New(s.db)
		case "EXTERNAL":
			c.SASLMech = external.New(s.db, c)
		case "SCRAM-SHA-256":
			c.SASLMech = scram.New(s.db, sha256.New)
		default:
			s.writeReply(c, c.Id(), RPL_SASLMECHS, cap.SASL.Value)
			s.writeReply(c, c.Id(), ERR_SASLFAIL)
			return
		}

		// TODO: all currently supported SASL mechanisms are client-first,
		// so we can be assured that the server should be sending a blank
		// challenge here. In the future if more mechanisms are added, this
		// will have to be reevaluated
		fmt.Fprintf(c, ":%s AUTHENTICATE +", s.Name)
		return
	}

	var decodedResp []byte
	// if this was not a continuation request (a request containing just '+')
	if m.Params[0] != "+" {
		// TODO: this kind of request can have a continuation if the initial
		// request byte count is over 400, so we should check to see if we
		// have a situation like this and append the messages together before
		// decoding
		// *("AUTHENTICATE" SP 400BASE64 CRLF) "AUTHENTICATE" SP (1*399BASE64 / "+") CRLF
		resp, err := base64.StdEncoding.DecodeString(m.Params[0])
		if err != nil {
			s.writeReply(c, c.Id(), ERR_SASLFAIL)
			return
		}
		decodedResp = resp
	}

	challenge, err := c.SASLMech.Next(decodedResp)
	if err != nil {
		s.writeReply(c, c.Id(), ERR_SASLFAIL)
		return
	}
	if challenge == nil {
		c.IsAuthenticated = true
		// TODO: what are <account> and <user>?
		s.writeReply(c, c.Id(), RPL_LOGGEDIN, c, c.SASLMech.Authn(), c.Id())
		s.writeReply(c, c.Id(), RPL_SASLSUCCESS)
		return
	}

	encodedChallenge := base64.StdEncoding.EncodeToString(challenge)
	fmt.Fprintf(c, ":%s AUTHENTICATE %s", s.Name, encodedChallenge)
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

	switch strings.ToUpper(m.Params[0]) {
	case "PASS":
		if len(m.Params) < 2 {
			s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "REGISTER PASS")
			return
		}
		pass := m.Params[1]

		plainCred := plain.NewCredential(c.Id(), pass)
		s.persistPlain(plainCred.Username, c.Nick, plainCred.Pass)

		salt := make([]byte, 16)
		rand.Read(salt)
		scramCred := scram.NewCredential(sha256.New, c.Id(), pass, salt, 4096)
		s.persistScram(scramCred.Username, c.Nick, scramCred.ServerKey, scramCred.StoredKey, scramCred.Salt, scramCred.Iteration)

	case "CERT":
		cert, err := c.Certificate()
		if err != nil {
			s.NOTICE(c, err.Error())
			return
		}
		cred := external.NewCredential(c.Id(), cert)
		s.persistExternal(cred.Username, c.Nick, cred.Cert)
	default:
		s.NOTICE(c, "Unsupported registration type "+m.Params[0])
		return
	}

	s.NOTICE(c, "Registered")
}

func (s *Server) persistPlain(username, nick string, pass []byte) {
	s.db.Exec("INSERT INTO sasl_plain VALUES(?, ?, ?)", username, nick, pass)
}

func (s *Server) persistScram(username, nick string, serverKey, storedKey, salt []byte, iteration int) {
	s.db.Exec("INSERT INTO sasl_scram VALUES(?, ?, ?, ?, ?, ?)", username, nick, serverKey, storedKey, salt, iteration)
}

func (s *Server) persistExternal(username, nick string, cert []byte) {
	s.db.Exec("INSERT INTO sasl_external VALUES(?, ?, ?)", username, nick, cert)
}

func (s *Server) userAccountForNickExists(n string) (username string) {
	s.db.QueryRow(`
		select username from sasl_plain where nick=?
		union
		select username from sasl_scram where nick=?
		union
		select username from sasl_external where nick=?
	`, n, n, n).Scan(&username)
	return
}
