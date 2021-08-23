package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mitchr/gossip/cap"
	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/mode"
	"github.com/mitchr/gossip/scan/msg"
	"github.com/mitchr/gossip/scan/wild"
	"golang.org/x/crypto/bcrypt"
)

type executor func(*Server, *client.Client, *msg.Message)

var commandMap = map[string]executor{
	// registration
	"PASS": PASS,
	"NICK": NICK,
	"USER": USER,
	"OPER": OPER,
	"QUIT": QUIT,
	"CAP":  CAP,

	// chanOps
	"JOIN":   JOIN,
	"PART":   PART,
	"TOPIC":  TOPIC,
	"NAMES":  NAMES,
	"LIST":   LIST,
	"INVITE": INVITE,
	"KICK":   KICK,

	// server queries
	"MOTD":   MOTD,
	"LUSERS": LUSERS,
	"TIME":   TIME,
	"MODE":   MODE,

	// user queries
	"WHO":   WHO,
	"WHOIS": WHOIS,

	// communication
	"PRIVMSG": PRIVMSG,
	"NOTICE":  NOTICE,
	"TAGMSG":  TAGMSG,

	// miscellaneous
	"PING":    PING,
	"PONG":    PONG,
	"WALLOPS": WALLOPS,
	"ERROR":   ERROR,

	"AWAY":   AWAY,
	"REHASH": REHASH,
}

func PASS(s *Server, c *client.Client, m *msg.Message) {
	if c.Is(client.Registered) {
		s.writeReply(c, c.Id(), ERR_ALREADYREGISTRED)
		return
	} else if len(m.Params) != 1 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "PASS")
		return
	}

	c.ServerPassAttempt = []byte(m.Params[0])
}

func NICK(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) != 1 {
		s.writeReply(c, c.Id(), ERR_NONICKNAMEGIVEN)
		return
	}

	nick := m.Params[0]

	// if nickname is already in use, send back error
	if _, ok := s.GetClient(nick); ok {
		s.writeReply(c, c.Id(), ERR_NICKNAMEINUSE, nick)
		return
	}

	// nick has been set previously
	if c.Nick != "" {
		// give back NICK to the caller and notify all the channels this
		// user is part of that their nick changed
		fmt.Fprintf(c, ":%s NICK :%s\r\n", c, nick)
		for _, v := range s.channelsOf(c) {
			fmt.Fprintf(v, ":%s NICK :%s\r\n", c, nick)

			// update member map entry
			m, _ := v.GetMember(c.Nick)
			v.DeleteMember(c.Nick)
			v.SetMember(nick, m)
		}

		// update client map entry
		s.DeleteClient(c.Nick)
		s.SetClient(nick, c)
		c.Nick = nick
	} else { // nick is being set for first time
		c.Nick = nick
		s.endRegistration(c)
	}
}

func USER(s *Server, c *client.Client, m *msg.Message) {
	// TODO: Ident Protocol

	if c.Is(client.Registered) {
		s.writeReply(c, c.Id(), ERR_ALREADYREGISTRED)
		return
	} else if len(m.Params) != 4 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "USER")
		return
	}

	modeBits, err := strconv.Atoi(m.Params[1])
	if err == nil {
		// only allow user to make themselves invis or wallops
		c.Mode = client.Mode(modeBits) & (client.Invisible | client.Wallops)
	}

	c.User = m.Params[0]
	c.Realname = m.Params[3]
	s.endRegistration(c)
}

func OPER(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) != 2 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "OPER")
		return
	}

	name := m.Params[0]
	pass := m.Params[1]

	// will fail if username doesn't exist or if pass is incorrect
	if bcrypt.CompareHashAndPassword(s.Ops[name], []byte(pass)) != nil {
		s.writeReply(c, c.Id(), ERR_PASSWDMISMATCH)
		return
	}

	c.Mode |= client.Op
	s.writeReply(c, c.Id(), RPL_YOUREOPER)
	fmt.Fprintf(c, ":%s MODE %s +o\r\n", s.Name, c.Nick)
}

func QUIT(s *Server, c *client.Client, m *msg.Message) {
	reason := "" // assume client does not send a reason for quit
	if len(m.Params) > 0 {
		reason = m.Params[0]
	}

	// send QUIT to all channels that client is connected to, and
	// remove that client from the channel
	for _, v := range s.channelsOf(c) {
		// as part of the JOIN contract, only members joined to the
		// quitting clients channels receive their quit message, not the
		// client themselves. isntead, they receive an error message from
		// the server signifying their depature.
		if len(v.Members) == 1 {
			s.DeleteChannel(v.String())
		} else {
			// message entire channel that client left
			v.DeleteMember(c.Nick)
			fmt.Fprintf(v, ":%s QUIT :%s\r\n", c, reason)
		}
	}

	s.ERROR(c, fmt.Sprintf("%s quit", c.Nick))
	c.Flush()
	c.Close()
	s.DeleteClient(c.Nick)
}

func (s *Server) endRegistration(c *client.Client) {
	if c.RegSuspended {
		return
	}
	if c.Nick == "" || c.User == "" { // tried to end without sending NICK & USER
		return
	}

	if s.Password != nil {
		if bcrypt.CompareHashAndPassword(s.Password, c.ServerPassAttempt) != nil {
			s.writeReply(c, c.Id(), ERR_PASSWDMISMATCH)
			s.ERROR(c, "Closing Link: "+s.Name+" (Bad Password)")
			c.Flush()
			c.Close()
			return
		}
	}

	c.Mode |= client.Registered
	s.SetClient(c.Nick, c)
	s.unknownLock.Lock()
	s.unknowns--
	s.unknownLock.Unlock()

	// send RPL_WELCOME and friends in acceptance
	s.writeReply(c, c.Id(), RPL_WELCOME, s.Network, c)
	s.writeReply(c, c.Id(), RPL_YOURHOST, s.Name)
	s.writeReply(c, c.Id(), RPL_CREATED, s.created)
	// serverName, version, userModes, chanModes
	s.writeReply(c, c.Id(), RPL_MYINFO, s.Name, "0", "ioOrw", "beliIkmstn")
	for _, support := range constructISUPPORT() {
		s.writeReply(c, c.Id(), RPL_ISUPPORT, support)
	}

	LUSERS(s, c, nil)
	MOTD(s, c, nil)

	// after registration burst, give clients max grants
	c.FillGrants()
}

func JOIN(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "JOIN")
		return
	}

	// when 'JOIN 0', PART from every channel client is a member of
	if m.Params[0] == "0" {
		for _, v := range s.channelsOf(c) {
			PART(s, c, &msg.Message{Params: []string{v.String()}})
		}
		return
	}

	chans := strings.Split(m.Params[0], ",")
	keys := make([]string, len(chans))
	if len(m.Params) >= 2 {
		// fill beginning of keys with the key m.Params
		k := strings.Split(m.Params[1], ",")
		copy(keys, k)
	}

	nameMsg := *m
	nameMsg.Command = "NAMES"
	for i := range chans {
		if ch, ok := s.GetChannel(chans[i]); ok { // channel already exists
			err := ch.Admit(c, keys[i])
			if err != nil {
				if err == channel.ErrKeyMissing {
					s.writeReply(c, c.Id(), ERR_BADCHANNELKEY, ch)
				} else if err == channel.ErrLimitReached { // not aceepting new clients
					s.writeReply(c, c.Id(), ERR_CHANNELISFULL, ch)
				} else if err == channel.ErrNotInvited {
					s.writeReply(c, c.Id(), ERR_INVITEONLYCHAN, ch)
				} else if err == channel.ErrBanned { // client is banned
					s.writeReply(c, c.Id(), ERR_BANNEDFROMCHAN, ch)
				}
				return
			}
			// send JOIN to all participants of channel
			fmt.Fprintf(ch, ":%s JOIN %s\r\n", c, ch)
			if ch.Topic != "" {
				// only send topic if it exists
				TOPIC(s, c, &msg.Message{Params: []string{ch.String()}})
			}
			nameMsg.Params = []string{ch.Name}
			NAMES(s, c, &nameMsg)
		} else { // create new channel
			chanChar := channel.ChanType(chans[i][0])
			chanName := chans[i][1:]

			if chanChar != channel.Remote && chanChar != channel.Local {
				s.writeReply(c, c.Id(), ERR_NOSUCHCHANNEL, chans[i])
				return
			}

			newChan := channel.New(chanName, chanChar)
			s.SetChannel(chans[i], newChan)
			newChan.SetMember(c.Nick, &channel.Member{Client: c, Prefix: string(channel.Founder)})
			fmt.Fprintf(c, ":%s JOIN %s\r\n", c, newChan)

			nameMsg.Params = []string{chans[i]}
			NAMES(s, c, &nameMsg)
		}
	}
}

func PART(s *Server, c *client.Client, m *msg.Message) {
	chans := strings.Split(m.Params[0], ",")

	reason := ""
	if len(m.Params) > 1 {
		reason = " :" + m.Params[1]
	}

	for _, v := range chans {
		ch := s.clientBelongstoChan(c, v)
		if ch == nil {
			return
		}

		fmt.Fprintf(ch, ":%s PART %s%s\r\n", c, ch, reason)
		if len(ch.Members) == 1 {
			s.DeleteChannel(ch.String())
		} else {
			ch.DeleteMember(c.Nick)
		}
	}
}

func TOPIC(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "TOPIC")
		return
	}

	ch := s.clientBelongstoChan(c, m.Params[0])
	if ch == nil {
		return
	}

	if len(m.Params) >= 2 { // modify topic
		if m, _ := ch.GetMember(c.Nick); !m.Is(channel.Operator) {
			s.writeReply(c, c.Id(), ERR_CHANOPRIVSNEEDED, ch)
			return
		}
		ch.Topic = m.Params[1]
		s.writeReply(c, c.Id(), RPL_TOPIC, ch, ch.Topic)
	} else {
		if ch.Topic == "" {
			s.writeReply(c, c.Id(), RPL_NOTOPIC, ch)
		} else { // give back existing topic
			s.writeReply(c, c.Id(), RPL_TOPIC, ch, ch.Topic)
		}
	}
}

func INVITE(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) != 2 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "INVITE")
		return
	}

	nick := m.Params[0]
	ch, ok := s.GetChannel(m.Params[1])
	if !ok { // channel exists
		return
	}

	sender, _ := ch.GetMember(c.Nick)
	recipient, _ := s.GetClient(nick)
	if sender == nil { // only members can invite
		s.writeReply(c, c.Id(), ERR_NOTONCHANNEL, ch)
		return
	} else if ch.Invite && sender.Is(channel.Operator) { // if invite mode set, only ops can send an invite
		s.writeReply(c, c.Id(), ERR_CHANOPRIVSNEEDED, ch)
		return
	} else if recipient == nil { // nick not on server
		s.writeReply(c, c.Id(), ERR_NOSUCHNICK, nick)
		return
	} else if _, ok := ch.GetMember(nick); ok { // can't invite a member who is already on channel
		s.writeReply(c, c.Id(), ERR_USERONCHANNEL, c, nick, ch)
		return
	}

	ch.Invited = append(ch.Invited, nick)
	fmt.Fprintf(recipient, ":%s INVITE %s %s\r\n", sender, nick, ch)
	s.writeReply(c, c.Id(), RPL_INVITING, ch, nick)
}

// if c belongs to the channel associated with chanName, return that
// channel. If it doesn't, or if the channel doesn't exist, write a
// numeric reply to the client and return nil.
func (s *Server) clientBelongstoChan(c *client.Client, chanName string) *channel.Channel {
	ch, ok := s.GetChannel(chanName)
	if !ok { // channel not found
		s.writeReply(c, c.Id(), ERR_NOSUCHCHANNEL, ch)
	} else {
		if _, ok := ch.GetMember(c.Nick); !ok { // client does not belong to channel
			s.writeReply(c, c.Id(), ERR_NOTONCHANNEL, ch)
		}
	}
	return ch
}

func KICK(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 2 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "KICK")
		return
	}

	comment := c.Nick
	if len(m.Params) == 3 {
		comment = m.Params[2]
	}

	chans := strings.Split(m.Params[0], ",")
	users := strings.Split(m.Params[1], ",")
	if len(chans) != 1 || len(chans) != len(users) {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "KICK")
		return
	}

	for i, v := range chans {
		ch, _ := s.GetChannel(v)
		if ch == nil {
			s.writeReply(c, c.Id(), ERR_NOSUCHCHANNEL, ch)
			return
		}
		self, _ := ch.GetMember(c.Nick)
		if self == nil {
			s.writeReply(c, c.Id(), ERR_NOTONCHANNEL, ch)
			return
		} else if !self.Is(channel.Operator) {
			s.writeReply(c, c.Id(), ERR_CHANOPRIVSNEEDED, ch)
			return
		}

		// If there are multiple channels, pair up the chans and users so
		// that one user is kicked per each chan
		if len(chans) != 1 {
			s.kickMember(c, ch, users[i], comment)
		} else {
			// If we are only given one channel, kick all users from it
			for _, u := range users {
				s.kickMember(c, ch, u, comment)
			}
		}
	}
}

// Given a nickname, determine if they belong to the Channel ch and kick
// them. If a comment is given, it will be sent along with the KICK.
func (s *Server) kickMember(c *client.Client, ch *channel.Channel, memberNick string, comment string) {
	u, _ := ch.GetMember(memberNick)
	if u == nil {
		s.writeReply(c, c.Id(), ERR_USERNOTINCHANNEL, u, ch)
		return
	}

	fmt.Fprintf(ch, ":%s KICK %s %s :%s\r\n", c, ch, u.Nick, comment)
	ch.DeleteMember(u.Nick)
}

func NAMES(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) == 0 {
		s.writeReply(c, c.Id(), RPL_ENDOFNAMES, "*")
		return
	}

	chans := strings.Split(m.Params[0], ",")
	for _, v := range chans {
		ch, _ := s.GetChannel(v)
		if ch == nil {
			s.writeReply(c, c.Id(), RPL_ENDOFNAMES, v)
		} else {
			_, ok := ch.GetMember(c.Nick)
			if ch.Secret && !ok { // chan is secret and client does not belong
				s.writeReply(c, c.Id(), RPL_ENDOFNAMES, v)
			} else {
				sym, members := constructNAMREPLY(ch, ok)
				s.writeReply(c, c.Id(), RPL_NAMREPLY, sym, ch, members)
				s.writeReply(c, c.Id(), RPL_ENDOFNAMES, v)
			}
		}
	}
}

// TODO: support ELIST m.Params
func LIST(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) == 0 {
		// reply with all channels that aren't secret
		for _, v := range s.channels {
			if !v.Secret {
				s.writeReply(c, c.Id(), RPL_LIST, v, len(v.Members), v.Topic)
			}
		}
	} else {
		for _, v := range strings.Split(m.Params[0], ",") {
			if ch, ok := s.GetChannel(v); ok {
				s.writeReply(c, c.Id(), RPL_LIST, ch, len(ch.Members), ch.Topic)
			}
		}
	}
	s.writeReply(c, c.Id(), RPL_LISTEND)
}

func MOTD(s *Server, c *client.Client, m *msg.Message) {
	if len(s.motd) == 0 {
		s.writeReply(c, c.Id(), ERR_NOMOTD)
		return
	}

	// TODO: should we also send RPL_LOCALUSERS and RPL_GLOBALUSERS?
	s.writeReply(c, c.Id(), RPL_MOTDSTART, s.Name)
	for _, v := range s.motd {
		s.writeReply(c, c.Id(), RPL_MOTD, v)
	}
	s.writeReply(c, c.Id(), RPL_ENDOFMOTD)
}

func LUSERS(s *Server, c *client.Client, m *msg.Message) {
	invis := 0
	ops := 0
	for _, v := range s.clients {
		if v.Is(client.Invisible) {
			invis++
			continue
		}
		if v.Is(client.Op) {
			ops++
		}
	}

	s.writeReply(c, c.Id(), RPL_LUSERCLIENT, len(s.clients), invis, 1)
	s.writeReply(c, c.Id(), RPL_LUSEROP, ops)
	s.unknownLock.Lock()
	s.writeReply(c, c.Id(), RPL_LUSERUNKNOWN, s.unknowns)
	s.unknownLock.Unlock()
	s.writeReply(c, c.Id(), RPL_LUSERCHANNELS, len(s.channels))
	s.writeReply(c, c.Id(), RPL_LUSERME, len(s.clients), 1)
}

func TIME(s *Server, c *client.Client, m *msg.Message) {
	s.writeReply(c, c.Id(), RPL_TIME, s.Name, time.Now().Local())
}

// TODO: support commands like this that intersperse the modechar and modem.Params MODE &oulu +b *!*@*.edu +e *!*@*.bu.edu
func MODE(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, c.Id(), RPL_UMODEIS, c.Mode)
		return
	}

	target := m.Params[0]
	if !isChannel(target) {
		client, ok := s.GetClient(target)
		if !ok {
			s.writeReply(c, c.Id(), ERR_NOSUCHNICK, target)
			return
		}
		if client.Nick != c.Nick { // can't modify another user
			s.writeReply(c, c.Id(), ERR_USERSDONTMATCH)
			return
		}

		if len(m.Params) == 2 { // modify own mode
			applied := ""
			for _, v := range mode.Parse([]byte(m.Params[1])) {
				found := c.ApplyMode(v)
				if !found {
					s.writeReply(c, c.Id(), ERR_UMODEUNKNOWNFLAG)
				} else {
					if v.Type == mode.Add {
						applied += "+" + string(v.ModeChar)
					} else if v.Type == mode.Remove {
						applied += "-" + string(v.ModeChar)
					} else {
						applied += string(v.ModeChar)
					}
				}
			}

			fmt.Fprintf(c, ":%s MODE %s %s\r\n", s.Name, c.Nick, applied)
		} else { // give back own mode
			s.writeReply(c, c.Id(), RPL_UMODEIS, c.Mode)
		}
	} else {
		ch, ok := s.GetChannel(target)
		if !ok {
			s.writeReply(c, c.Id(), ERR_NOSUCHCHANNEL, ch)
			return
		}

		if len(m.Params) == 1 { // modeStr not given, give back channel modes
			modeStr, params := ch.Modes()
			if len(params) != 0 {
				modeStr += " "
			}

			s.writeReply(c, c.Id(), RPL_CHANNELMODEIS, ch, modeStr, strings.Join(params, " "))
		} else { // modeStr given
			modes := mode.Parse([]byte(m.Params[1]))
			channel.PopulateModeParams(modes, m.Params[2:])
			applied := ""
			for _, m := range modes {
				if m.Param == "" {
					switch m.ModeChar {
					case 'b':
						for _, v := range ch.Ban {
							s.writeReply(c, c.Id(), RPL_BANLIST, ch, v)
						}
						s.writeReply(c, c.Id(), RPL_ENDOFBANLIST, ch)
						continue
					case 'e':
						for _, v := range ch.BanExcept {
							s.writeReply(c, c.Id(), RPL_EXCEPTLIST, ch, v)
						}
						s.writeReply(c, c.Id(), RPL_ENDOFEXCEPTLIST, ch)
						continue
					case 'I':
						for _, v := range ch.InviteExcept {
							s.writeReply(c, c.Id(), RPL_INVITELIST, ch, v)
						}
						s.writeReply(c, c.Id(), RPL_ENDOFINVITELIST, ch)
						continue
					}
				}
				a, err := ch.ApplyMode(m)
				applied += a
				if errors.Is(err, channel.ErrNeedMoreParams) {
					s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, err)
				} else if errors.Is(err, channel.ErrUnknownMode) {
					s.writeReply(c, c.Id(), ERR_UNKNOWNMODE, err, ch)
				} else if errors.Is(err, channel.ErrNotInChan) {
					s.writeReply(c, c.Id(), ERR_USERNOTINCHANNEL, err, ch)
				}
			}
			// only write final MODE to channel if any mode was actually altered
			if applied != "" {
				fmt.Fprintf(ch, ":%s MODE %s\r\n", s.Name, applied)
			}
		}
	}
}

func WHO(s *Server, c *client.Client, m *msg.Message) {
	mask := "*"
	if len(m.Params) > 0 {
		mask = m.Params[0]
	}

	// send WHOREPLY to every noninvisible client who does not share a
	// channel with the sender
	if mask == "*" || mask == "0" {
		for _, v := range s.clients {
			if v.Is(client.Invisible) {
				continue
			}
			if !s.haveChanInCommon(c, v) {
				flags := "H"
				if v.Is(client.Away) {
					flags = "G"
				}
				if v.Is(client.Op) {
					flags += "*"
				}
				s.writeReply(c, c.Id(), RPL_WHOREPLY, "*", v.User, v.Host, s.Name, v.Nick, flags, v.Realname)
			}
		}
		s.writeReply(c, c.Id(), RPL_ENDOFWHO, mask)
		return
	}

	onlyOps := false
	if len(m.Params) > 1 && m.Params[1] == "o" {
		onlyOps = true
	}

	// given a mask, match against all channels. if no channels match,
	// treat the mask as a client prefix and match against all clients.
	for _, v := range s.channels {
		if wild.Match(mask, strings.ToLower(v.String())) {
			for _, member := range v.Members {
				if onlyOps && !member.Client.Is(client.Op) { // skip nonops
					continue
				}
				flags := "H"
				if member.Client.Is(client.Away) {
					flags = "G"
				}
				if member.Client.Is(client.Op) {
					flags += "*"
				}
				if member.Is(channel.Operator) {
					flags += "@"
				}
				if member.Is(channel.Voice) {
					flags += "+"
				}
				s.writeReply(c, c.Id(), RPL_WHOREPLY, v, member.User, member.Host, s.Name, member.Nick, flags, member.Realname)
			}
			s.writeReply(c, c.Id(), RPL_ENDOFWHO, mask)
			return
		}
	}

	// no channel results found
	for _, v := range s.clients {
		if wild.Match(mask, strings.ToLower(v.String())) {
			if onlyOps && !v.Is(client.Op) { // skip nonops
				continue
			}

			flags := "H"
			if v.Is(client.Away) {
				flags = "G"
			}
			if v.Is(client.Op) {
				flags += "*"
			}
			s.writeReply(c, c.Id(), RPL_WHOREPLY, "*", v.User, v.Host, s.Name, v.Nick, flags, v.Realname)
		}
	}
	s.writeReply(c, c.Id(), RPL_ENDOFWHO, mask)
}

// we only support the <mask> *( "," <mask> ) parameter, target seems
// pointless with only one server in the tree
func WHOIS(s *Server, c *client.Client, m *msg.Message) {
	// silently ignore empty m.Params
	if len(m.Params) < 1 {
		return
	}

	masks := strings.Split(strings.ToLower(m.Params[0]), ",")
	for _, m := range masks {
		for _, v := range s.clients {
			if wild.Match(m, v.Nick) {
				s.writeReply(c, c.Id(), RPL_WHOISUSER, v.Nick, v.User, v.Host, v.Realname)
				s.writeReply(c, c.Id(), RPL_WHOISSERVER, v.Nick, s.Name, "wip irc server")
				if v.Is(client.Op) {
					s.writeReply(c, c.Id(), RPL_WHOISOPERATOR, v.Nick)
				}
				if v == c || c.Is(client.Op) { // querying whois on self or self is an op
					if v.IsSecure() {
						certPrint, err := v.CertificateFingerprint()
						if err == nil {
							s.writeReply(c, c.Id(), RPL_WHOISCERTFP, v.Nick, certPrint)
						}
					}
				}
				s.writeReply(c, c.Id(), RPL_WHOISIDLE, v.Nick, time.Since(v.Idle).Round(time.Second).Seconds(), v.JoinTime)

				chans := []string{}
				for _, k := range s.channels {
					_, senderBelongs := k.GetMember(c.Nick)
					member, clientBelongs := k.GetMember(v.Nick)

					// if client is invisible or this channel is secret, only send
					// a response if the sender shares a channel with this client
					if k.Secret || v.Is(client.Invisible) {
						if !(senderBelongs && clientBelongs) {
							continue
						}
					}
					chans = append(chans, string(member.HighestPrefix())+k.Name)
				}
				chanParam := ""
				if len(chans) > 0 {
					chanParam = " :" + strings.Join(chans, " ")
				}
				s.writeReply(c, c.Id(), RPL_WHOISCHANNELS, v.Nick, chanParam)
			}
		}
	}
	s.writeReply(c, c.Id(), RPL_ENDOFWHOIS)
}

func PRIVMSG(s *Server, c *client.Client, m *msg.Message) { s.communicate(m, c) }
func NOTICE(s *Server, c *client.Client, m *msg.Message)  { s.communicate(m, c) }

// communicate is used for PRIVMSG/NOTICE. if notice is set to true,
// then error replies from the server will not be sent.
func (s *Server) communicate(m *msg.Message, c *client.Client) {
	msg := *m
	// "Tags without the client-only prefix MUST be removed by the
	// server before being relayed with any message to another client."
	msg.TrimNonClientTags()
	msg.Nick = c.Nick
	msg.Host = c.Host
	msg.User = c.User

	skipReplies := false
	if m.Command == "NOTICE" || m.Command == "TAGMSG" {
		skipReplies = true
	}

	if len(m.Params) < 2 && m.Command != "TAGMSG" {
		if !skipReplies {
			s.writeReply(c, c.Id(), ERR_NOTEXTTOSEND)
		}
		return
	}

	recipients := strings.Split(m.Params[0], ",")
	for _, v := range recipients {
		msg.Params[0] = v

		// TODO: support sending to only a specific user mode in channel (i.e., PRIVMSG %#buffy)
		if isChannel(v) {
			ch, _ := s.GetChannel(v)
			if ch == nil { // channel doesn't exist
				if !skipReplies {
					s.writeReply(c, c.Id(), ERR_NOSUCHCHANNEL, v)
				}
				continue
			}

			self, _ := ch.GetMember(c.Nick)
			if self == nil {
				if ch.NoExternal {
					// chan does not allow external messages; client needs to join
					if !skipReplies {
						s.writeReply(c, c.Id(), ERR_CANNOTSENDTOCHAN, ch)
					}
					continue
				}
			} else if ch.Moderated && self.Prefix == "" {
				// member has no mode, so they cannot speak in a moderated chan
				if !skipReplies {
					s.writeReply(c, c.Id(), ERR_CANNOTSENDTOCHAN, ch)
				}
				continue
			}

			// write to everybody else in the chan besides self
			for _, member := range ch.Members {
				if member.Client == c {
					continue
				}
				if msg.Command == "TAGMSG" && !member.Caps[cap.MessageTags] {
					continue
				}
				if !member.Caps[cap.MessageTags] {
					fmt.Fprint(member, msg.RemoveAllTags().String()+"\r\n")
				} else {
					fmt.Fprint(member, msg.String()+"\r\n")
				}
				member.Flush()
			}
		} else { // client->client
			target, ok := s.GetClient(v)
			if !ok {
				if !skipReplies {
					s.writeReply(c, c.Id(), ERR_NOSUCHNICK, v)
				}
				continue
			}

			if target.Is(client.Away) {
				s.writeReply(c, c.Id(), RPL_AWAY, target.Nick, target.AwayMsg)
				continue
			}
			if msg.Command == "TAGMSG" && !target.Caps[cap.MessageTags] {
				continue
			}
			if !target.Caps[cap.MessageTags] {
				fmt.Fprint(target, msg.RemoveAllTags().String()+"\r\n")
			} else {
				fmt.Fprint(target, msg.String()+"\r\n")
			}
			target.Flush()
		}
	}
}

func PING(s *Server, c *client.Client, m *msg.Message) {
	fmt.Fprintf(c, ":%s PONG\r\n", s.Name)
}

func PONG(s *Server, c *client.Client, m *msg.Message) {
	c.PONG <- struct{}{}
}

// this is currently a noop, as a server should only accept ERROR
// commands from other servers
func ERROR(s *Server, c *client.Client, m *msg.Message) {}

func AWAY(s *Server, c *client.Client, m *msg.Message) {
	// remove away
	if len(m.Params) == 0 {
		c.AwayMsg = ""
		c.Mode &^= client.Away
		s.writeReply(c, c.Id(), RPL_UNAWAY)
		return
	}

	c.AwayMsg = m.Params[0]
	c.Mode |= client.Away
	s.writeReply(c, c.Id(), RPL_NOWAWAY)
}

func REHASH(s *Server, c *client.Client, m *msg.Message) {
	if !c.Is(client.Op) {
		s.writeReply(c, c.Id(), ERR_NOPRIVILEGES)
		return
	}

	conf, _ := NewConfig(s.path)
	s.Config = conf
	s.writeReply(c, c.Id(), RPL_REHASHING, s.path)
}

func WALLOPS(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) != 1 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "WALLOPS")
		return
	}

	for _, v := range s.clients {
		if v.Is(client.Wallops) {
			fmt.Fprintf(v, "%s WALLOPS %s", s.Name, m.Params[1])
		}
	}
}

func (s *Server) executeMessage(m *msg.Message, c *client.Client) {
	upper := strings.ToUpper(m.Command)
	// ignore unregistered user commands until registration completes
	if !c.Is(client.Registered) && (upper != "CAP" && upper != "NICK" && upper != "USER" && upper != "PASS") {
		return
	}

	if e, ok := commandMap[upper]; ok {
		c.Idle = time.Now()
		e(s, c, m)
	} else {
		s.writeReply(c, c.Id(), ERR_UNKNOWNCOMMAND, m.Command)
	}
	c.Flush()
}

// determine if the given string is a channel
func isChannel(s string) bool {
	return s[0] == byte(channel.Remote) || s[0] == byte(channel.Local)
}
