package server

import (
	"fmt"
	"log"

	"github.com/mitchr/gossip/client"
)

// a message represents a single irc message
type message struct {
	tags             map[string]string
	nick, user, host string // source/prefix information
	command          string
	middle           []string // command parameters
	trailing         string   // also a command parameter but after ':'
}

func (m message) String() string {
	return fmt.Sprintf("nick: %s\nuser: %s\nhost: %s\ncommand: %s\nmiddle: %v\ntrailing: %s\n", m.nick, m.user, m.host, m.command, m.middle, m.trailing)
}

// merge middle and trailing into one slice
func (m message) parameters() []string {
	return append(m.middle, m.trailing)
}

func (s *Server) executeMessage(m *message, c *client.Client) {
	// TODO: don't allow client to access any other commands besides
	// CAP, NICK, USER, PASS if they are unregistered
	switch m.command {
	case "NICK":
		if len(m.middle) != 1 {
			s.numericReply(c, 433, "No nickname given")
			return
		}

		nick := m.middle[0]

		// if nickname is already in use, send back error
		if s.Clients.SearchNick(nick) != nil {
			s.numericReply(c, 433, "Nickname is already in use")
			return
		}

		c.Nick = nick
		s.endRegistration(c)
	case "USER":
		// TODO: Ident Protocol

		params := m.parameters()

		if c.Registered {
			s.numericReply(c, 462, "You may not reregister")
			return
		} else if len(params) != 4 {
			s.numericReply(c, 461, "Not enough parameters")
			return
		}

		if params[1] != "0" || params[2] != "*" {
			// TODO: find appropriate error code
			s.numericReply(c, 0, "Wrong protocol")
			return
		}

		c.User = params[0]
		c.Realname = params[3]
		s.endRegistration(c)
	default:
		s.numericReply(c, 421, fmt.Sprintf("Unknown command '%s'", m.command))
	}
}

// TODO: If we add capability negotiation, then that logic will have to go here as well
// when a client successfully calls USER/NICK, they are registered
func (s *Server) endRegistration(c *client.Client) {
	if c.Nick != "" && c.User != "" {
		c.Registered = true

		// send RPL_WELCOME and friends in acceptance
		c.Write(s.numericReply(c, RPL_WELCOME, fmt.Sprintf("Welcome to the Internet Relay Network %s[!%s@%s]", c.Nick, c.User, c.Host.String())))
		c.Write(s.numericReply(c, RPL_YOURHOST, fmt.Sprintf("Your host is %s", s.Listener.Addr().String())))
		c.Write(s.numericReply(c, RPL_CREATED, fmt.Sprintf("This server was created %s", s.Created)))

		// TODO: send proper response messages
		c.Write(s.numericReply(c, RPL_MYINFO, ""))
		c.Write(s.numericReply(c, RPL_ISUPPORT, ""))

		// TODO: send LUSERS and MOTD
		log.Println("successfully registered client")
	}
}
