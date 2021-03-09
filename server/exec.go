package server

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/msg"
)

type executor func(*Server, *client.Client, []string)

var commandMap = map[string]executor{
	// registration
	"PASS": PASS,
	"NICK": NICK,
	"USER": USER,
	"QUIT": QUIT,

	// chanOps
	"JOIN":  JOIN,
	"PART":  PART,
	"TOPIC": TOPIC,
	"NAMES": NAMES,

	// server queries
	"MOTD":   MOTD,
	"LUSERS": LUSERS,
	"MODE":   MODE,

	// communication
	"PRIVMSG": PRIVMSG,
	"NOTICE":  NOTICE,

	// miscellaneous
	"PING":    PING,
	"PONG":    PONG,
	"WALLOPS": WALLOPS,
	"ERROR":   ERROR,
}

func PASS(s *Server, c *client.Client, params []string) {
	if c.BarredFromPass {
		return
	}
	if c.Registered {
		s.numericReply(c, ERR_ALREADYREGISTRED)
		return
	} else if len(params) != 1 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "PASS")
		return
	}

	c.ServerPassAttempt = params[0]
}

func NICK(s *Server, c *client.Client, params []string) {
	c.BarredFromPass = true

	if len(params) != 1 {
		s.numericReply(c, ERR_NONICKNAMEGIVEN)
		return
	}

	nick := params[0]

	// if nickname is already in use, send back error
	if s.Clients[nick] != nil {
		// TODO: if user is changing their already existing username,
		// this will be fine. otherwise, trying to send back c.Nick will
		// just be an empty string, whereas the spec says you should give
		// back a '*' for an unused/unitialized parameter
		s.numericReply(c, ERR_NICKNAMEINUSE, nick)
		return
	}

	c.Nick = nick
	s.endRegistration(c)
}

func USER(s *Server, c *client.Client, params []string) {
	c.BarredFromPass = true
	// TODO: Ident Protocol

	if c.Registered {
		s.numericReply(c, ERR_ALREADYREGISTRED)
		return
	} else if len(params) != 4 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "USER")
		return
	}

	modeBits, err := strconv.Atoi(params[1])
	if err == nil {
		// only allow user to make themselves invis or wallops
		c.Mode = client.Mode(modeBits) & (client.Invisible | client.Wallops)
	}

	c.User = params[0]
	c.Realname = params[3]
	s.endRegistration(c)
}

func QUIT(s *Server, c *client.Client, params []string) {
	reason := "" // assume client does not send a reason for quit
	if len(params) > 0 {
		reason = params[0]
	}

	// send QUIT to all channels that client is connected to, and
	// remove that client from the channel
	for _, v := range s.channelsOf(c) {
		s.removeFromChannel(c, v, fmt.Sprintf(":%s QUIT :%s", c, reason))
	}

	c.Cancel()
}

// TODO: If we add capability negotiation, then that logic will have to go here as well
func (s *Server) endRegistration(c *client.Client) {
	if c.Nick != "" && c.User != "" {
		if c.ServerPassAttempt != s.password {
			s.numericReply(c, ERR_PASSWDMISMATCH)
			s.ERROR(c, "Closing Link: "+s.Listener.Addr().String()+" (Bad Password)")
			c.Cancel()
			return
		}
		c.Registered = true
		s.Clients[c.Nick] = c

		// send RPL_WELCOME and friends in acceptance
		s.numericReply(c, RPL_WELCOME, c)
		s.numericReply(c, RPL_YOURHOST, s.Listener.Addr())
		s.numericReply(c, RPL_CREATED, s.Created)
		// TODO: send proper response messages
		s.numericReply(c, RPL_MYINFO, s.Listener.Addr(), "", "", "")
		s.numericReply(c, RPL_ISUPPORT, "")

		LUSERS(s, c, nil)
		MOTD(s, c, nil)

		// start PING timer
		go func() {
			ticker := time.NewTicker(time.Minute * 3)
			// wait 3 minutes, send PING
			// if client doesn't respond with a PONG in 10 seconds, kick them
			for {
				<-ticker.C
				c.ExpectingPONG = true
				c.Write(fmt.Sprintf(":%s PING %s", s.Listener.Addr(), c.Nick))
				time.Sleep(time.Second * 10)
				if c.ExpectingPONG {
					c.Cancel()
					ticker.Stop()
					return
				}
			}
		}()
	}
}

func JOIN(s *Server, c *client.Client, params []string) {
	if len(params) < 1 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "JOIN")
		return
	}

	//when 'JOIN 0', PART from every channel client is a member of
	if params[0] == "0" {
		for _, v := range s.channelsOf(c) {
			PART(s, c, []string{v.String()})
		}
		return
	}

	// TODO: support channel keys
	// split all given channels by comma separator
	chans := strings.Split(params[0], ",")
	for _, v := range chans {
		if ch, ok := s.Channels[v]; ok { // channel already exists
			ch.Members[c.Nick] = channel.NewMember(c, "")
			// send JOIN to all participants of channel
			ch.Write(fmt.Sprintf(":%s JOIN %s", c, v))

			// TODO: send RPL_TOPIC/RPL_NOTOPIC and RPL_NAMREPLY to current joiner
		} else { // create new channel
			chanChar := channel.ChanType(v[0])
			chanName := v[1:]

			if chanChar != channel.Remote && chanChar != channel.Local {
				// TODO: is there a response code for this case?
				// maybe 403 nosuchchannel?
				return
			}

			ch := channel.New(chanName, chanChar)
			s.Channels[ch.String()] = ch
			ch.Members[c.Nick] = channel.NewMember(c, string(channel.Founder))
			c.Write(fmt.Sprintf(":%s JOIN %s", c, ch))
		}
	}
}

func PART(s *Server, c *client.Client, params []string) {
	chans := strings.Split(params[0], ",")
	var reason string
	if len(params) >= 2 {
		reason = params[1]
	}
	for _, v := range chans {
		// TODO: could refactor this below if check into a func like
		// 'chanExistsandUserBelongs'; this logic is also used in TOPIC and
		// will probably be used elsewhere!
		if ch, ok := s.Channels[v]; !ok { // channel not found
			s.numericReply(c, ERR_NOSUCHCHANNEL, ch)
		} else {
			if ch.Members[c.Nick] == nil { // client does not belong to channel
				s.numericReply(c, ERR_NOTONCHANNEL, v)
				return
			}

			if reason == "" {
				s.removeFromChannel(c, ch, fmt.Sprintf("%s PART %s", c, ch))
			} else {
				s.removeFromChannel(c, ch, fmt.Sprintf("%s PART %s :%s", c, ch, reason))
			}
		}
	}
}

func TOPIC(s *Server, c *client.Client, params []string) {
	if len(params) < 1 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "TOPIC")
		return
	}

	if ch := s.Channels[params[0]]; ch != nil {
		if _, belongs := ch.Members[c.Nick]; belongs {
			if len(params) == 2 { // modify topic
				// TODO: don't allow modifying topic if client doesn't have
				// proper privileges 'ERR_CHANOPRIVSNEEDED'
				ch.Topic = params[1]
				s.numericReply(c, RPL_TOPIC, ch, ch.Topic)
			} else {
				if ch.Topic == "" {
					s.numericReply(c, RPL_NOTOPIC, ch)
				} else { // give back existing topic
					s.numericReply(c, RPL_TOPIC, ch, ch.Topic)
				}
			}

		} else {
			s.numericReply(c, ERR_NOTONCHANNEL, ch)
			return
		}
	} else {
		s.numericReply(c, ERR_NOSUCHCHANNEL, ch)
		return
	}
}

func NAMES(s *Server, c *client.Client, params []string) {
	if len(params) != 1 {
		s.numericReply(c, RPL_ENDOFNAMES, "*")
	}
}

func MOTD(s *Server, c *client.Client, params []string) {
	// TODO: should we also send RPL_LOCALUSERS and RPL_GLOBALUSERS?
	s.numericReply(c, RPL_MOTDSTART, s.Listener.Addr())
	s.numericReply(c, RPL_MOTD, "") // TODO: parse MOTD from config file or something
	s.numericReply(c, RPL_ENDOFMOTD)
}

func LUSERS(s *Server, c *client.Client, params []string) {
	s.numericReply(c, RPL_LUSERCLIENT, len(s.Clients), 0, 0)
	s.numericReply(c, RPL_LUSEROP, 0)
	s.numericReply(c, RPL_LUSERUNKNOWN, 0)
	s.numericReply(c, RPL_LUSERCHANNELS, len(s.Channels))
	s.numericReply(c, RPL_LUSERME, len(s.Clients), 0)
}

func MODE(s *Server, c *client.Client, params []string) {
	if len(params) < 1 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "MODE")
		return
	}

	target := params[0]
	if !isChannel(target) {
		if client, ok := s.Clients[target]; ok {
			if client.Nick != c.Nick { // can't mofidy another user
				s.numericReply(c, ERR_USERSDONTMATCH)
				return
			}

			if len(params) == 2 { // modify own mode
				found := c.ApplyMode([]byte(params[1]))
				if !found {
					s.numericReply(c, ERR_UMODEUNKNOWNFLAG)
				}
				c.Write(fmt.Sprintf(":%s MODE %s %s", s.Listener.Addr(), c.Nick, params[1]))
			} else { // give back own mode
				s.numericReply(c, RPL_UMODEIS, c.Mode)
			}
		} else {
			s.numericReply(c, ERR_NOSUCHNICK, target)
		}
	}
}

func PRIVMSG(s *Server, c *client.Client, params []string) {
	s.communicate(params, c, false)
}

func NOTICE(s *Server, c *client.Client, params []string) {
	s.communicate(params, c, true)
}

// communicate is used for PRIVMSG/NOTICE. if notice is set to true,
// then error replies from the server will not be sent.
func (s *Server) communicate(params []string, c *client.Client, notice bool) {
	command := "PRIVMSG"
	if notice {
		command = "NOTICE"
	}

	if !notice && len(params) < 2 {
		s.numericReply(c, ERR_NOTEXTTOSEND)
		return
	}

	recipients := strings.Split(params[0], ",")
	msg := params[1]
	for _, v := range recipients {
		if isChannel(v) {
			if ch, ok := s.Channels[v]; ok {
				ch.Write(fmt.Sprintf(":%s %s %s :%s", c, command, v, msg))
			} else if !notice {
				s.numericReply(c, ERR_NOSUCHCHANNEL, v)
			}
		} else {
			if client, ok := s.Clients[v]; ok {
				client.Write(fmt.Sprintf(":%s %s %s :%s", c, command, v, msg))
			} else if !notice {
				s.numericReply(c, ERR_NOSUCHNICK, v)
			}
		}
	}
}

func PING(s *Server, c *client.Client, params []string) {
	// TODO: params can contain other servers, in which case the PING
	// will have to be redirected. For now, we can just assume that any
	// PING from a connected client is meant for this server
	c.Write(fmt.Sprintf(":%s PONG", s.Listener.Addr()))
}

func PONG(s *Server, c *client.Client, params []string) {
	c.ExpectingPONG = false
	// TODO: ignore for now, but like PING, PONG can be meant for
	// multiple servers so we need to investigate params
	return
}

// TODO: this is currently a noop, as a server should only accept ERROR
// commands from other servers
func ERROR(s *Server, c *client.Client, params []string) {
	return
}

func WALLOPS(s *Server, c *client.Client, params []string) {
	if len(params) != 1 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "WALLOPS")
		return
	}
	// TODO: only allows WALLOPS from another server; can be abused by clients
	for _, v := range s.Clients {
		if v.Mode&client.Wallops == client.Wallops {
			v.Write(fmt.Sprintf("%s WALLOPS %s", s.Listener.Addr(), params[1]))
		}
	}
}

func (s *Server) executeMessage(m *msg.Message, c *client.Client) {
	// ignore unregistered user commands until registration completes
	if !c.Registered && (m.Command != "CAP" && m.Command != "NICK" && m.Command != "USER" && m.Command != "PASS") {
		return
	}

	if e, ok := commandMap[m.Command]; ok {
		e(s, c, m.Parameters())
	} else {
		s.numericReply(c, ERR_UNKNOWNCOMMAND, m.Command)
	}
}

// determine if the given string is a channel
func isChannel(s string) bool {
	return s[0] == byte(channel.Remote) || s[0] == byte(channel.Local)
}
