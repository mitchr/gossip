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

// TODO: print tags as well
func (m message) String() string {
	var prefix string
	if m.user != "" {
		prefix = fmt.Sprintf(":%s!%s@%s", m.nick, m.user, m.host)
	} else if m.host != "" {
		prefix = fmt.Sprintf(":%s@%s", m.nick, m.host)
	} else if m.nick != "" {
		prefix = ":" + m.nick
	} else {
		prefix = ":*"
}

	var params string
	for _, v := range m.middle {
		params += v + " "
	}
	if m.trailing != "" {
		params += ":" + m.trailing
	} else {
		params = params[:len(params)-1] // trim trailing space
	}

	return fmt.Sprintf("%s %s %s\r\n", prefix, m.command, params)
}

// merge middle and trailing into one slice
func (m message) parameters() []string {
	if m.trailing == "" {
		return m.middle
	}
	return append(m.middle, m.trailing)
}

func (s *Server) executeMessage(m *message, c *client.Client) {
	// TODO: don't allow client to access any other commands besides
	// CAP, NICK, USER, PASS if they are unregistered
	params := m.parameters()

	switch m.command {
	case "NICK":
		if len(m.middle) != 1 {
			c.Write(fmt.Sprintf(ERR_NONICKNAMEGIVEN, s.Listener.Addr(), c.Nick))
			return
		}

		nick := m.middle[0]

		// if nickname is already in use, send back error
		if s.Clients.Find(nick) != nil {
			// TODO: if user is changing their already existing username,
			// this will be fine. otherwise, trying to send back c.Nick will
			// just be an empty string, whereas the spec says you should give
			// back a '*' for an unused/unitialized parameter
			c.Write(fmt.Sprintf(ERR_NICKNAMEINUSE, s.Listener.Addr(), c.Nick, nick))
			return
		}

		c.Nick = nick
		s.endRegistration(c)
	case "USER":
		// TODO: Ident Protocol

		if c.Registered {
			c.Write(fmt.Sprintf(ERR_ALREADYREGISTRED, s.Listener.Addr(), c.Nick))
			return
		} else if len(params) != 4 {
			c.Write(fmt.Sprintf(ERR_NEEDMOREPARAMS, s.Listener.Addr(), c.Nick, m.command))
			return
		}

		if params[1] != "0" || params[2] != "*" {
			// TODO: find appropriate error code
			// s.numericReply(c, 0, "Wrong protocol")
			return
		}

		c.User = params[0]
		c.Realname = params[3]
		s.endRegistration(c)
	default:
		c.Write(fmt.Sprintf(ERR_UNKNOWNCOMMAND, s.Listener.Addr(), c.Nick, m.command))
	}
}

// TODO: If we add capability negotiation, then that logic will have to go here as well
// when a client successfully calls USER/NICK, they are registered
func (s *Server) endRegistration(c *client.Client) {
	if c.Nick != "" && c.User != "" {
		c.Registered = true

		// send RPL_WELCOME and friends in acceptance
		c.Write(fmt.Sprintf(RPL_WELCOME, s.Listener.Addr(), c.Nick, c.Prefix()))
		c.Write(fmt.Sprintf(RPL_YOURHOST, s.Listener.Addr(), c.Nick, s.Listener.Addr()))
		c.Write(fmt.Sprintf(RPL_CREATED, s.Listener.Addr(), c.Nick, s.Created))

		// TODO: send proper response messages
		// c.Write(s.numericReply(c, RPL_MYINFO, ""))
		// c.Write(s.numericReply(c, RPL_ISUPPORT, ""))

		// TODO: send LUSERS and MOTD
		log.Println("successfully registered client")
	}
}
