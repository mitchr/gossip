package server

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"

	cap "github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/sasl"
	"github.com/mitchr/gossip/sasl/external"
	"github.com/mitchr/gossip/sasl/plain"
	"github.com/mitchr/gossip/sasl/scram"
	"github.com/mitchr/gossip/scan/msg"
)

func AUTHENTICATE(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	_, saslNone := c.SASLMech.(sasl.None)
	// // "If the client completes registration (with CAP END, NICK, USER and
	// // any other necessary messages) while the SASL authentication is
	// // still in progress, the server SHOULD abort it and send a 906
	// // numeric, then register the client without authentication"
	// if c.Is(client.Registered) && !saslNone && !c.IsAuthenticated {
	// 	c.SASLMech = nil
	// 	return prepMessage(ERR_SASLABORTED, s.Name, c.Id())
	// }

	// client must have requested the SASL capability, and has not yet registered
	// if !c.Caps[cap.SASL.Name] || c.Is(client.Registered) {
	// 	return prepMessage(ERR_SASLFAIL, s.Name, c.Id())
	// }

	// "If the client attempts to issue the AUTHENTICATE command after
	// already authenticating successfully, the server MUST reject it
	// with a 907 numeric"
	if c.IsAuthenticated {
		return prepMessage(ERR_SASLALREADY, s.Name, c.Id())
	}

	if len(m.Params) == 0 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "AUTHENTICATE")
	}

	if m.Params[0] == "*" {
		c.SASLMech = nil
		return prepMessage(ERR_SASLABORTED, s.Name, c.Id())
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
			buff := &msg.Buffer{}
			buff.AddMsg(prepMessage(RPL_SASLMECHS, s.Name, c.Id(), cap.SASL.Value))
			buff.AddMsg(prepMessage(ERR_SASLFAIL, s.Name, c.Id()))
			return buff
		}

		// TODO: all currently supported SASL mechanisms are client-first,
		// so we can be assured that the server should be sending a blank
		// challenge here. In the future if more mechanisms are added, this
		// will have to be reevaluated
		return msg.New(nil, s.Name, "", "", "AUTHENTICATE", []string{"+"}, false)
	}

	// if this was not a continuation request
	// *("AUTHENTICATE" SP 400BASE64 CRLF) "AUTHENTICATE" SP (1*399BASE64 / "+") CRLF
	if m.Params[0] != "+" {
		c.AuthCtx = append(c.AuthCtx, []byte(m.Params[0])...)
	}
	if len(m.Params[0]) == 400 {
		return nil
	}

	// clear authorization context
	defer func() { c.AuthCtx = nil }()

	decodedResp := make([]byte, base64.StdEncoding.DecodedLen(len(c.AuthCtx)))
	n, err := base64.StdEncoding.Decode(decodedResp, c.AuthCtx)
	if err != nil {
		return prepMessage(ERR_SASLFAIL, s.Name, c.Id())
	}

	challenge, err := c.SASLMech.Next(decodedResp[:n])
	if err != nil {
		return prepMessage(ERR_SASLFAIL, s.Name, c.Id())
	}
	if challenge == nil {
		c.IsAuthenticated = true
		buff := &msg.Buffer{}
		buff.AddMsg(prepMessage(RPL_LOGGEDIN, s.Name, c.Id(), c, c.SASLMech.Authn(), c.Id()))
		buff.AddMsg(prepMessage(RPL_SASLSUCCESS, s.Name, c.Id()))
		if c.Caps[cap.AccountNotify.Name] {
			buff.AddMsg(msg.New(nil, c.Nick, c.User, c.Host, "ACCOUNT", []string{c.SASLMech.Authn()}, false))
		}
		s.accountNotify(c)
		return buff
	}

	encodedChallenge := base64.StdEncoding.EncodeToString(challenge)
	return msg.New(nil, s.Name, "", "", "AUTHENTICATE", []string{encodedChallenge}, false)
}

func (s *Server) accountNotify(c *client.Client) {
	// if c.Caps[cap.AccountNotify.Name] {
	// 	c.WriteMessage(msg.New(nil, c.Nick, c.User, c.Host, "ACCOUNT", []string{c.SASLMech.Authn()}, false))
	// }

	// keep track of all clients in the same channel with c
	clients := make(map[*client.Client]bool)
	chans := s.channelsOf(c)
	for _, v := range chans {
		v.ForAllMembersExcept(c, func(m *channel.Member) {
			if clients[m.Client] || !m.Caps[cap.AccountNotify.Name] {
				return
			}
			clients[m.Client] = true
			m.WriteMessage(msg.New(nil, c.Nick, c.User, c.Host, "ACCOUNT", []string{c.SASLMech.Authn()}, false))
			s.writeReply(m.Client, msg.New(nil, "", "", "", "ACCOUNT", []string{c.SASLMech.Authn()}, false))
		})
	}

	s.notify(c, msg.New(nil, c.Nick, c.User, c.Host, "ACCOUNT", []string{c.SASLMech.Authn()}, false), cap.AccountNotify)
}

// REGISTER is nonstandard
// for now, username is assumed to be the same as the current client's nick
// REGISTER PASS <pass>
// REGISTER CERT
// REGISTER <channel>
func REGISTER(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) == 0 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "REGISTER")
	}

	switch arg := strings.ToUpper(m.Params[0]); {
	case arg == "PASS":
		if len(m.Params) < 2 {
			return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "REGISTER PASS")
		}
		pass := m.Params[1]

		plainCred := plain.NewCredential(c.Id(), pass)
		s.persistPlain(plainCred.Username, c.Nick, plainCred.Pass)

		salt := make([]byte, 16)
		rand.Read(salt)
		scramCred := scram.NewCredential(sha256.New, c.Id(), pass, salt, 4096)
		s.persistScram(scramCred.Username, c.Nick, scramCred.ServerKey, scramCred.StoredKey, scramCred.Salt, scramCred.Iteration)

	case arg == "CERT":
		cert, err := c.Certificate()
		if err != nil {
			return s.NOTICE(c, err.Error())
		}
		cred := external.NewCredential(c.Id(), cert)
		s.persistExternal(cred.Username, c.Nick, cred.Cert)

	case isValidChannelString(arg):
		// channel must exist already, sender must be an op in that channel,
		// and the channel should not already be registered
		ch, exists := s.getChannel(arg)
		if !exists {
			return s.NOTICE(c, fmt.Sprintf("Channel %s does not exist", arg))
		}

		m, belongs := ch.GetMember(c.Id())
		if !belongs || !m.Is(channel.Operator) {
			return s.NOTICE(c, "You are not a channel operator")
		}

		if s.chanAlreadyRegistered(arg) {
			return s.NOTICE(c, "Channel already registered")
		}

		s.persistChan(c.Id(), arg)
		buff := &msg.Buffer{}
		buff.AddMsg(MODE(s, c, msg.New(nil, c.Nick, c.User, c.Host, "MODE", []string{arg, "+q", c.Nick}, false)))
		buff.AddMsg(s.NOTICE(c, "Registered"))
		return buff

	default:
		return s.NOTICE(c, "Unsupported registration type "+m.Params[0])
	}

	return s.NOTICE(c, "Registered")
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

func (s *Server) persistChan(owner, channel string) {
	s.db.Exec("INSERT INTO channels VALUES(?, ?)", owner, channel)
}

func (s *Server) chanAlreadyRegistered(channel string) bool {
	r := s.db.QueryRow("select chan from channels where chan=?", channel)
	return r.Err() == sql.ErrNoRows
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
