package server

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/msg"
)

func (s *Server) executeMessage(m *msg.Message, c *client.Client) {
	// ignore unregistered user commands until registration completes
	if !c.Registered && (m.Command != "CAP" && m.Command != "NICK" && m.Command != "USER" && m.Command != "PASS") {
		return
	}

	params := m.Parameters()

	switch m.Command {
	case "NICK":
		if len(params) != 1 {
			c.Write(fmt.Sprintf(ERR_NONICKNAMEGIVEN, s.Listener.Addr(), c.Nick))
			return
		}

		nick := params[0]

		// if nickname is already in use, send back error
		if s.Clients[nick] != nil {
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
			c.Write(fmt.Sprintf(ERR_NEEDMOREPARAMS, s.Listener.Addr(), c.Nick, m.Command))
			return
		}

		modeBits, err := strconv.Atoi(params[1])
		if err != nil {
			// TODO: really, no error code for this?
			log.Println(err)
			return
		}

		// only allow user to make themselves invis or wallops
		c.Mode = client.Mode(modeBits) & (client.Invisible | client.Wallops)
		c.User = params[0]
		c.Realname = params[3]
		s.endRegistration(c)
	case "PRIVMSG":
		s.communicate(params, c, false)
	case "NOTICE":
		s.communicate(params, c, true)
	case "JOIN":
		if len(params) < 1 {
			c.Write(fmt.Sprintf(ERR_NEEDMOREPARAMS, s.Listener.Addr(), c.Nick, m.Command))
			return
		}

		//when 'JOIN 0', PART from every channel client is a member of
		if params[0] == "0" {
			for _, v := range s.channelsOf(c) {
				s.PART(c, v.String())
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
				ch.Write(fmt.Sprintf(":%s JOIN %s\r\n", c, v))

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
				c.Write(fmt.Sprintf(":%s JOIN %s\r\n", c, ch))
			}
		}
	case "PART":
		// TODO: support <reason> parameter
		chans := strings.Split(params[0], ",")
		for _, v := range chans {
			s.PART(c, v)
		}
	case "TOPIC":
		if len(params) < 1 {
			c.Write(fmt.Sprintf(ERR_NEEDMOREPARAMS, s.Listener.Addr(), c.Nick, m.Command))
			return
		}

		if ch := s.Channels[params[0]]; ch != nil {
			if _, belongs := ch.Members[c.Nick]; belongs {
				if len(params) == 2 { // modify topic
					// TODO: don't allow modifying topic if client doesn't have
					// proper privileges 'ERR_CHANOPRIVSNEEDED'
					ch.Topic = params[1]
					c.Write(fmt.Sprintf(RPL_TOPIC, s.Listener.Addr(), c.Nick, ch, ch.Topic))
				} else {
					if ch.Topic == "" {
						c.Write(fmt.Sprintf(RPL_NOTOPIC, s.Listener.Addr(), c.Nick, ch))
					} else { // give back existing topic
						c.Write(fmt.Sprintf(RPL_TOPIC, s.Listener.Addr(), c.Nick, ch, ch.Topic))
					}
				}

			} else {
				c.Write(fmt.Sprintf(ERR_NOTONCHANNEL, s.Listener.Addr(), c.Nick, ch))
				return
			}
		} else {
			c.Write(fmt.Sprintf(ERR_NOSUCHCHANNEL, s.Listener.Addr(), c.Nick, ch))
			return
		}
	case "NAMES":
		if len(params) != 1 {
			c.Write(fmt.Sprintf(RPL_ENDOFNAMES, s.Listener.Addr(), c.Nick, "*"))
		}
	case "LUSERS":
		s.LUSERS(c)
	case "MOTD":
		s.MOTD(c)
	case "MODE":
		if len(params) < 1 {
			c.Write(fmt.Sprintf(ERR_NEEDMOREPARAMS, s.Listener.Addr(), c.Nick, m.Command))
			return
		}

		target := params[0]
		if !isChannel(target) {
			if client, ok := s.Clients[target]; ok {
				if client.Nick != c.Nick { // can't mofidy another user
					c.Write(fmt.Sprintf(ERR_USERSDONTMATCH, s.Listener.Addr(), c.Nick))
					return
				}

				if len(params) == 2 { // modify own mode
					found := c.ApplyMode([]byte(params[1]))
					if !found {
						c.Write(fmt.Sprintf(ERR_UMODEUNKNOWNFLAG, s.Listener.Addr(), c.Nick))
					}
					c.Write(fmt.Sprintf(":%s MODE %s %s\r\n", s.Listener.Addr(), c.Nick, params[1]))
				} else { // give back own mode
					c.Write(fmt.Sprintf(RPL_UMODEIS, s.Listener.Addr(), c.Nick, c.Mode))
				}
			} else {
				c.Write(fmt.Sprintf(ERR_NOSUCHNICK, s.Listener.Addr(), c.Nick, target))
			}
		}

	case "QUIT":
		reason := "" // assume client does not send a reason for quit
		if len(params) > 0 {
			reason = params[0]
		}

		// send QUIT to all channels that client is connected to, and
		// remove that client from the channel
		for _, v := range s.channelsOf(c) {
			s.removeFromChannel(c, v, fmt.Sprintf(":%s QUIT :%s\r\n", c, reason))
		}

		c.Cancel()
	case "PING":
		// TODO: params can contain other servers, in which case the PING
		// will have to be redirected. For now, we can just assume that any
		// PING from a connected client is meant for this server
		c.Write(fmt.Sprintf(":%s PONG", s.Listener.Addr()))
	case "PONG":
		c.ExpectingPONG = false
		// TODO: ignore for now, but like PING, PONG can be meant for
		// multiple servers so we need to investigate params
		return
	case "WALLOPS":
		if len(params) != 1 {
			c.Write(fmt.Sprintf(ERR_NEEDMOREPARAMS, s.Listener.Addr(), c.Nick, m.Command))
			return
		}
		// TODO: only allows WALLOPS from another server; can be abused by clients
		for _, v := range s.Clients {
			if v.Mode&client.Wallops == client.Wallops {
				v.Write(fmt.Sprintf("%s WALLOPS %s\r\n", s.Listener.Addr(), params[1]))
			}
		}
	default:
		c.Write(fmt.Sprintf(ERR_UNKNOWNCOMMAND, s.Listener.Addr(), c.Nick, m.Command))
	}
}

// communicate is used for PRIVMSG/NOTICE. if notice is set to true,
// then error replies from the server will not be sent.
func (s *Server) communicate(params []string, c *client.Client, notice bool) {
	command := "PRIVMSG"
	if notice {
		command = "NOTICE"
	}

	if !notice && len(params) < 2 {
		c.Write(fmt.Sprintf(ERR_NOTEXTTOSEND, s.Listener.Addr(), c.Nick))
		return
	}

	recipients := strings.Split(params[0], ",")
	msg := params[1]
	for _, v := range recipients {
		if isChannel(v) {
			if ch, ok := s.Channels[v]; ok {
				ch.Write(fmt.Sprintf(":%s %s %s :%s\r\n", c, command, v, msg))
			} else if !notice {
				c.Write(fmt.Sprintf(ERR_NOSUCHCHANNEL, s.Listener.Addr(), c.Nick, v))
			}
		} else {
			if client, ok := s.Clients[v]; ok {
				client.Write(fmt.Sprintf(":%s %s %s :%s\r\n", c, command, v, msg))
			} else if !notice {
				c.Write(fmt.Sprintf(ERR_NOSUCHNICK, s.Listener.Addr(), c.Nick, v))
			}
		}
	}
}

// TODO: actually calculate invisible and connected servers for response
func (s *Server) LUSERS(c *client.Client) {
	c.Write(fmt.Sprintf(RPL_LUSERCLIENT, s.Listener.Addr(), c.Nick, len(s.Clients), 0, 0) +
		fmt.Sprintf(RPL_LUSEROP, s.Listener.Addr(), c.Nick, 0) +
		fmt.Sprintf(RPL_LUSERUNKNOWN, s.Listener.Addr(), c.Nick, 0) +
		fmt.Sprintf(RPL_LUSERCHANNELS, s.Listener.Addr(), c.Nick, len(s.Channels)) +
		fmt.Sprintf(RPL_LUSERME, s.Listener.Addr(), c.Nick, len(s.Clients), 0),
	)
	// TODO: should we also send RPL_LOCALUSERS and RPL_GLOBALUSERS?
}

func (s *Server) MOTD(c *client.Client) {
	c.Write(fmt.Sprintf(RPL_MOTDSTART, s.Listener.Addr(), c.Nick, s.Listener.Addr()))
	c.Write(fmt.Sprintf(RPL_MOTD, s.Listener.Addr(), c.Nick, "")) // TODO: parse MOTD from config file or something
	c.Write(fmt.Sprintf(RPL_ENDOFMOTD, s.Listener.Addr(), c.Nick))
}

func (s *Server) PART(client *client.Client, chanStr string) {
	// TODO: could refactor this below if check into a func like
	// 'chanExistsandUserBelongs'; this logic is also used in TOPIC and
	// will probably be used elsewhere!
	if ch, ok := s.Channels[chanStr]; !ok { // channel not found
		client.Write(fmt.Sprintf(ERR_NOSUCHCHANNEL, s.Listener.Addr(), client.Nick, ch))
	} else {
		if ch.Members[client.Nick] == nil { // client does not belong to channel
			client.Write(fmt.Sprintf(ERR_NOTONCHANNEL, s.Listener.Addr(), client.Nick, chanStr))
			return
		}

		s.removeFromChannel(client, ch, fmt.Sprintf("%s PART %s\r\n", client, ch))
	}
}

// TODO: If we add capability negotiation, then that logic will have to go here as well
// when a client successfully calls USER/NICK, they are registered
func (s *Server) endRegistration(c *client.Client) {
	if c.Nick != "" && c.User != "" {
		c.Registered = true
		s.Clients[c.Nick] = c

		// send RPL_WELCOME and friends in acceptance
		c.Write(fmt.Sprintf(RPL_WELCOME, s.Listener.Addr(), c.Nick, c) +
			fmt.Sprintf(RPL_YOURHOST, s.Listener.Addr(), c.Nick, s.Listener.Addr()) +
			fmt.Sprintf(RPL_CREATED, s.Listener.Addr(), c.Nick, s.Created) +
			// TODO: send proper response messages
			fmt.Sprintf(RPL_MYINFO, s.Listener.Addr(), c.Nick, s.Listener.Addr(), "", "", "") +
			fmt.Sprintf(RPL_ISUPPORT, s.Listener.Addr(), c.Nick, ""),
		)
		s.LUSERS(c)
		s.MOTD(c)

		// start PING timer
		go func() {
			ticker := time.NewTicker(time.Minute * 3)
			// wait 3 minutes, send PING
			// if client doesn't respond with a PONG in 10 seconds, kick them
			for {
				<-ticker.C
				c.ExpectingPONG = true
				c.Write(fmt.Sprintf(":%s PING %s\r\n", s.Listener.Addr(), c.Nick))
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

// determine if the given string is a channel
func isChannel(s string) bool {
	return s[0] == byte(channel.Remote) || s[0] == byte(channel.Local)
}
