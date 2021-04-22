package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
	"github.com/mitchr/gossip/scan/wild"
)

type executor func(*Server, *client.Client, ...string)

var commandMap = map[string]executor{
	// registration
	"PASS": PASS,
	"NICK": NICK,
	"USER": USER,
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

	// miscellaneous
	"PING":    PING,
	"PONG":    PONG,
	"WALLOPS": WALLOPS,
	"ERROR":   ERROR,

	"AWAY": AWAY,
}

func PASS(s *Server, c *client.Client, params ...string) {
	// client is barred from entering password if they have previously
	// sent a NICK or USER command
	if c.Nick != "" || c.User != "" {
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

func NICK(s *Server, c *client.Client, params ...string) {
	if len(params) != 1 {
		s.numericReply(c, ERR_NONICKNAMEGIVEN)
		return
	}

	nick := params[0]

	// if nickname is already in use, send back error
	if _, ok := s.GetClient(nick); ok {
		s.numericReply(c, ERR_NICKNAMEINUSE, nick)
		return
	}

	// nick has been set previously
	if c.Nick != "" {
		// give back NICK to the caller and notify all the channels this
		// user is part of that their nick changed
		c.Write(fmt.Sprintf(":%s NICK :%s", c, nick))
		for _, v := range s.channelsOf(c) {
			v.Write(fmt.Sprintf(":%s NICK :%s", c, nick))

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

func USER(s *Server, c *client.Client, params ...string) {
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

func QUIT(s *Server, c *client.Client, params ...string) {
	reason := "" // assume client does not send a reason for quit
	if len(params) > 0 {
		reason = params[0]
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
			v.Write(fmt.Sprintf(":%s QUIT :%s", c, reason))
		}
	}

	s.ERROR(c, c.Nick+" quit")
	c.Cancel()
}

func (s *Server) endRegistration(c *client.Client) {
	if c.RegSuspended {
		return
	}
	if c.Nick == "" || c.User == "" {
		return
	}

	if c.ServerPassAttempt != s.password {
		s.numericReply(c, ERR_PASSWDMISMATCH)
		s.ERROR(c, "Closing Link: "+s.listener.Addr().String()+" (Bad Password)")
		c.Cancel()
		return
	}
	c.Registered = true
	s.SetClient(c.Nick, c)
	s.unknowns--

	// send RPL_WELCOME and friends in acceptance
	s.numericReply(c, RPL_WELCOME, c)
	s.numericReply(c, RPL_YOURHOST, s.listener.Addr())
	s.numericReply(c, RPL_CREATED, s.created)
	// serverName, version, userModes, chanModes
	s.numericReply(c, RPL_MYINFO, s.listener.Addr(), "0", "ioOrw", "beliIkmstn")
	// TODO: send proper response messages
	s.numericReply(c, RPL_ISUPPORT, "")

	LUSERS(s, c)
	MOTD(s, c)

	// start PING timer
	go func() {
		ticker := time.NewTicker(time.Minute * 5)
		defer ticker.Stop()

		// every 5 minutes, send PING
		// if client doesn't respond with a PONG in 10 seconds, kick them
		for {
			<-ticker.C
			c.ExpectingPONG = true
			c.Write(fmt.Sprintf(":%s PING %s", s.listener.Addr(), c.Nick))
			time.Sleep(time.Second * 10)
			if c.ExpectingPONG {
				s.ERROR(c, "Closing Link: PING/PONG timeout")
				c.Cancel()
				return
			}
		}
	}()
}

func JOIN(s *Server, c *client.Client, params ...string) {
	if len(params) < 1 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "JOIN")
		return
	}

	// when 'JOIN 0', PART from every channel client is a member of
	if params[0] == "0" {
		for _, v := range s.channelsOf(c) {
			PART(s, c, v.String())
		}
		return
	}

	chans := strings.Split(params[0], ",")
	keys := make([]string, len(chans))
	if len(params) >= 2 {
		keys = strings.Split(params[1], ",")
		// fill remaining slots with empty string, since no key was given
		// for remaining channel params
		keys = append(keys, make([]string, len(chans)-len(keys))...)
	}

	for i := range chans {
		if ch, ok := s.GetChannel(chans[i]); ok { // channel already exists
			err := ch.Admit(c, keys[i])
			if err != nil {
				if err == channel.KeyErr {
					s.numericReply(c, ERR_BADCHANNELKEY, ch)
				} else if err == channel.LimitErr { // not aceepting new clients
					s.numericReply(c, ERR_CHANNELISFULL, ch)
				} else if err == channel.InviteErr {
					s.numericReply(c, ERR_INVITEONLYCHAN, ch)
				} else if err == channel.BanErr { // client is banned
					s.numericReply(c, ERR_BANNEDFROMCHAN, ch)
				}
				return
			}
			// send JOIN to all participants of channel
			ch.Write(fmt.Sprintf(":%s JOIN %s", c, ch))
			if ch.Topic != "" {
				// only send topic if it exists
				TOPIC(s, c, ch.String())
			}
			sym, members := constructNAMREPLY(ch, ok)
			s.numericReply(c, RPL_NAMREPLY, sym, ch, members)
		} else { // create new channel
			chanChar := channel.ChanType(chans[i][0])
			chanName := chans[i][1:]

			if chanChar != channel.Remote && chanChar != channel.Local {
				// TODO: is there a response code for this case?
				// maybe 403 nosuchchannel?
				return
			}

			newChan := channel.New(chanName, chanChar)
			s.SetChannel(chans[i], newChan)
			newChan.SetMember(c.Nick, &channel.Member{c, string(channel.Founder)})
			c.Write(fmt.Sprintf(":%s JOIN %s", c, newChan))
		}
	}
}

func PART(s *Server, c *client.Client, params ...string) {
	chans := strings.Split(params[0], ",")

	reason := ""
	if len(params) > 1 {
		reason = " :" + params[1]
	}

	for _, v := range chans {
		ch := s.clientBelongstoChan(c, v)
		if ch == nil {
			return
		}

		ch.Write(fmt.Sprintf(":%s PART %s%s", c, ch, reason))
		if len(ch.Members) == 1 {
			s.DeleteChannel(ch.String())
		} else {
			ch.DeleteMember(c.Nick)
		}
	}
}

func TOPIC(s *Server, c *client.Client, params ...string) {
	if len(params) < 1 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "TOPIC")
		return
	}

	ch := s.clientBelongstoChan(c, params[0])
	if ch == nil {
		return
	}

	if len(params) >= 2 { // modify topic
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
}

func INVITE(s *Server, c *client.Client, params ...string) {
	if len(params) != 2 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "INVITE")
		return
	}

	nick := params[0]
	ch, ok := s.GetChannel(params[1])
	if !ok { // channel exists
		return
	}

	sender, _ := ch.GetMember(c.Nick)
	recipient, _ := s.GetClient(nick)
	if sender == nil { // only members can invite
		s.numericReply(c, ERR_NOTONCHANNEL, ch)
		return
	} else if ch.Invite && sender.Is(channel.Operator) { // if invite mode set, only ops can send an invite
		s.numericReply(c, ERR_CHANOPRIVSNEEDED, ch)
		return
	} else if recipient == nil { // nick not on server
		s.numericReply(c, ERR_NOSUCHNICK, nick)
		return
	} else if _, ok := ch.GetMember(nick); ok { // can't invite a member who is already on channel
		s.numericReply(c, ERR_USERONCHANNEL, c, nick, ch)
		return
	}

	ch.Invited = append(ch.Invited, nick)
	recipient.Write(fmt.Sprintf(":%s INVITE %s %s\r\n", sender, nick, ch))
	s.numericReply(c, RPL_INVITING, ch, nick)
}

// if c belongs to the channel associated with chanName, return that
// channel. If it doesn't, or if the channel doesn't exist, write a
// numeric reply to the client and return nil.
func (s *Server) clientBelongstoChan(c *client.Client, chanName string) *channel.Channel {
	ch, ok := s.GetChannel(chanName)
	if !ok { // channel not found
		s.numericReply(c, ERR_NOSUCHCHANNEL, ch)
	} else {
		if _, ok := ch.GetMember(c.Nick); !ok { // client does not belong to channel
			s.numericReply(c, ERR_NOTONCHANNEL, ch)
		}
	}
	return ch
}

func KICK(s *Server, c *client.Client, params ...string) {
	if len(params) != 2 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "KICK")
		return
	}

	comment := c.Nick
	if len(params) == 3 {
		comment = params[2]
	}

	chans := strings.Split(params[0], ",")
	users := strings.Split(params[1], ",")

	if len(chans) == 1 {
		ch, _ := s.GetChannel(chans[0])
		if ch == nil {
			s.numericReply(c, ERR_NOSUCHCHANNEL, ch)
			return
		}
		self, _ := ch.GetMember(c.Nick)
		if self == nil {
			s.numericReply(c, ERR_NOTONCHANNEL, ch)
			return
		} else if !self.Is(channel.Operator) {
			s.numericReply(c, ERR_CHANOPRIVSNEEDED, ch)
			return
		}

		for _, v := range users {
			u, _ := ch.GetMember(v)
			if u == nil {
				s.numericReply(c, ERR_USERNOTINCHANNEL, u, ch)
				continue
			}

			ch.Write(fmt.Sprintf(":%s KICK %s %s :%s\r\n", c, ch, u.Nick, comment))
			ch.DeleteMember(u.Nick)
		}
	} else if len(chans) == len(users) {
		for i := 0; i < len(chans); i++ {
			ch, _ := s.GetChannel(chans[i])
			if ch == nil {
				s.numericReply(c, ERR_NOSUCHCHANNEL, ch)
				continue
			}
			self, _ := ch.GetMember(c.Nick)
			if self == nil {
				s.numericReply(c, ERR_NOTONCHANNEL, ch)
				continue
			} else if !self.Is(channel.Operator) {
				s.numericReply(c, ERR_CHANOPRIVSNEEDED, ch)
				continue
			}

			u, _ := ch.GetMember(users[i])
			if u == nil {
				s.numericReply(c, ERR_USERNOTINCHANNEL, u, ch)
				continue
			}

			ch.Write(fmt.Sprintf(":%s KICK %s %s :%s\r\n", c, ch, u.Nick, comment))
			ch.DeleteMember(u.Nick)
		}
	} else {
		// "there MUST be either one channel parameter and multiple user
		// parameter, or as many channel parameters as there are user
		// parameters" - RFC2812

		// TODO: okay so the spec actually doesn't say what to do in this case
		// I assume NEEDMOREPARAMS is sufficient
		s.numericReply(c, ERR_NEEDMOREPARAMS, "KICK")
		return
	}
}

func NAMES(s *Server, c *client.Client, params ...string) {
	if len(params) == 0 {
		s.numericReply(c, RPL_ENDOFNAMES, "*")
		return
	}

	chans := strings.Split(params[0], ",")
	for _, v := range chans {
		ch, _ := s.GetChannel(v)
		if ch == nil {
			s.numericReply(c, RPL_ENDOFNAMES, v)
		} else {
			_, ok := ch.GetMember(c.Nick)
			if ch.Secret && !ok { // chan is secret and client does not belong
				s.numericReply(c, RPL_ENDOFNAMES, v)
			} else {
				sym, members := constructNAMREPLY(ch, ok)
				s.numericReply(c, RPL_NAMREPLY, sym, ch, members)
				s.numericReply(c, RPL_ENDOFNAMES, v)
			}
		}
	}
}

// given a channel, construct a NAMREPLY for all the members. if
// invisibles is true, include invisible members in the response; this
// should only be done if the requesting client is also a member of the
// channel
func constructNAMREPLY(c *channel.Channel, invisibles bool) (symbol string, members string) {
	symbol = "="
	if c.Secret {
		symbol = "@"
	}

	for k, v := range c.Members {
		// if not inluding invisible clients, and this client is invisible
		if !invisibles && v.Client.Is(client.Invisible) {
			continue
		}
		if v.Prefix != "" {
			// TODO: only use the member's highest membership mode
			members += string(v.Prefix[0])
		}
		members += k + " "
	}
	return symbol, members[0 : len(members)-1]
}

// TODO: support ELIST params
func LIST(s *Server, c *client.Client, params ...string) {
	if len(params) == 0 {
		// reply with all channels that aren't secret
		for _, v := range s.channels {
			if !v.Secret {
				s.numericReply(c, RPL_LIST, v, len(v.Members), v.Topic)
			}
		}
	} else {
		for _, v := range strings.Split(params[0], ",") {
			if ch, ok := s.GetChannel(v); ok {
				s.numericReply(c, RPL_LIST, ch, len(ch.Members), ch.Topic)
			}
		}
	}
	s.numericReply(c, RPL_LISTEND)
}

func MOTD(s *Server, c *client.Client, params ...string) {
	// TODO: should we also send RPL_LOCALUSERS and RPL_GLOBALUSERS?
	s.numericReply(c, RPL_MOTDSTART, s.listener.Addr())
	s.numericReply(c, RPL_MOTD, "") // TODO: parse MOTD from config file or something
	s.numericReply(c, RPL_ENDOFMOTD)
}

func LUSERS(s *Server, c *client.Client, params ...string) {
	invis := 0
	for _, v := range s.clients {
		if v.Is(client.Invisible) {
			invis++
		}
	}
	ops := 0
	for _, v := range s.clients {
		if v.Is(client.Op) {
			ops++
		}
	}

	s.numericReply(c, RPL_LUSERCLIENT, len(s.clients), invis, 1)
	s.numericReply(c, RPL_LUSEROP, ops)
	s.numericReply(c, RPL_LUSERUNKNOWN, s.unknowns)
	s.numericReply(c, RPL_LUSERCHANNELS, len(s.channels))
	s.numericReply(c, RPL_LUSERME, len(s.clients), 1)
}

func TIME(s *Server, c *client.Client, params ...string) {
	s.numericReply(c, RPL_TIME, s.listener.Addr(), time.Now().Local())
}

// TODO: support commands like this that intersperse the modechar and modeparams MODE &oulu +b *!*@*.edu +e *!*@*.bu.edu
func MODE(s *Server, c *client.Client, params ...string) {
	if len(params) < 1 {
		s.numericReply(c, RPL_UMODEIS, c.Mode)
		return
	}

	target := params[0]
	if !isChannel(target) {
		if client, ok := s.GetClient(target); ok {
			if client.Nick != c.Nick { // can't modify another user
				s.numericReply(c, ERR_USERSDONTMATCH)
				return
			}

			if len(params) == 2 { // modify own mode
				found := c.ApplyMode([]byte(params[1]))
				if !found {
					s.numericReply(c, ERR_UMODEUNKNOWNFLAG)
				}
				c.Write(fmt.Sprintf(":%s MODE %s %s", s.listener.Addr(), c.Nick, params[1]))
			} else { // give back own mode
				s.numericReply(c, RPL_UMODEIS, c.Mode)
			}
		} else {
			s.numericReply(c, ERR_NOSUCHNICK, target)
		}
	} else {
		ch, ok := s.GetChannel(target)
		if !ok {
			s.numericReply(c, ERR_NOSUCHCHANNEL, ch)
			return
		}

		if len(params) == 1 { // modeStr not given, give back channel modes
			modeStr, params := ch.Modes()
			if len(params) != 0 {
				modeStr += " "
			}

			s.numericReply(c, RPL_CHANNELMODEIS, ch, modeStr, strings.Join(params, " "))
		} else { // modeStr given
			applied, err := ch.ApplyMode([]byte(params[1]), params[2:])
			var u *channel.UnknownModeErr
			var n *channel.NotInChanErr
			if errors.As(err, &u) {
				s.numericReply(c, ERR_UNKNOWNMODE, u, ch)
			} else if errors.As(err, &n) {
				s.numericReply(c, ERR_USERNOTINCHANNEL, n, ch)
			}
			ch.Write(fmt.Sprintf(":%s MODE %s", s.listener.Addr(), applied))
		}
	}
}

func (s *Server) haveChanInCommon(c1, c2 *client.Client) bool {
	for _, ch := range s.channels {
		_, c1Belongs := ch.GetMember(c1.Nick)
		_, c2Belongs := ch.GetMember(c2.Nick)
		if c1Belongs && c2Belongs {
			return true
		}
	}
	return false
}

func WHO(s *Server, c *client.Client, params ...string) {
	mask := "*"
	if len(params) > 0 {
		mask = params[0]
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
				s.numericReply(c, RPL_WHOREPLY, "*", v.User, v.Host, s.listener.Addr(), v.Nick, flags, v.Realname)
			}
		}
		s.numericReply(c, RPL_ENDOFWHO, mask)
		return
	}

	onlyOps := false
	if len(params) > 1 && params[1] == "o" {
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
				s.numericReply(c, RPL_WHOREPLY, v, member.User, member.Host, s.listener.Addr(), member.Nick, flags, member.Realname)
			}
			s.numericReply(c, RPL_ENDOFWHO, mask)
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
			s.numericReply(c, RPL_WHOREPLY, "*", v.User, v.Host, s.listener.Addr(), v.Nick, flags, v.Realname)
		}
	}
	s.numericReply(c, RPL_ENDOFWHO, mask)
}

// we only support the <mask> *( "," <mask> ) parameter, target seems
// pointless with only one server in the tree
func WHOIS(s *Server, c *client.Client, params ...string) {
	// silently ignore empty params
	if len(params) < 1 {
		return
	}

	masks := strings.Split(strings.ToLower(params[0]), ",")
	for _, m := range masks {
		for _, v := range s.clients {
			if wild.Match(m, v.Nick) {
				s.numericReply(c, RPL_WHOISUSER, v.Nick, v.User, v.Host, v.Realname)
				s.numericReply(c, RPL_WHOISSERVER, v.Nick, s.listener.Addr(), "wip irc server")
				if v.Is(client.Op) {
					s.numericReply(c, RPL_WHOISOPERATOR, v.Nick)
				}
				// TODO: format these correctly
				s.numericReply(c, RPL_WHOISIDLE)
				s.numericReply(c, RPL_WHOISCHANNELS)
			}
		}
	}
	s.numericReply(c, RPL_ENDOFWHOIS)
}

func PRIVMSG(s *Server, c *client.Client, params ...string) { s.communicate(params, c, false) }
func NOTICE(s *Server, c *client.Client, params ...string)  { s.communicate(params, c, true) }

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
			ch, _ := s.GetChannel(v)
			if ch == nil && !notice { // channel doesn't exist
				s.numericReply(c, ERR_NOSUCHCHANNEL, v)
				return
			}

			m, _ := ch.GetMember(c.Nick)
			if m == nil {
				if ch.NoExternal {
					// chan does not allow external messages; client needs to join
					s.numericReply(c, ERR_CANNOTSENDTOCHAN, ch)
					return
				}
			} else if ch.Moderated && m.Prefix == "" {
				// member has no mode, so they cannot speak in a moderated chan
				s.numericReply(c, ERR_CANNOTSENDTOCHAN, ch)
				return
			}

			// write to everybody else in the chan besides self
			for _, m := range ch.Members {
				if m.Client == c {
					continue
				}
				m.Write(fmt.Sprintf(":%s %s %s :%s", c, command, v, msg))
			}
		} else { // client->client
			if target, ok := s.GetClient(v); ok {
				if target.Is(client.Away) {
					s.numericReply(c, RPL_AWAY, target.Nick, target.AwayMsg)
				} else {
					target.Write(fmt.Sprintf(":%s %s %s :%s", c, command, v, msg))
				}
			} else if !notice {
				s.numericReply(c, ERR_NOSUCHNICK, v)
			}
		}
	}
}

func PING(s *Server, c *client.Client, params ...string) {
	c.Write(fmt.Sprintf(":%s PONG", s.listener.Addr()))
}

func PONG(s *Server, c *client.Client, params ...string) {
	c.ExpectingPONG = false
}

// this is currently a noop, as a server should only accept ERROR
// commands from other servers
func ERROR(s *Server, c *client.Client, params ...string) { return }

func AWAY(s *Server, c *client.Client, params ...string) {
	// remove away
	if len(params) == 0 {
		c.AwayMsg = ""
		c.Mode &^= client.Away
		s.numericReply(c, RPL_UNAWAY)
		return
	}

	c.AwayMsg = params[0]
	c.Mode |= client.Away
	s.numericReply(c, RPL_NOWAWAY)
	return
}

func WALLOPS(s *Server, c *client.Client, params ...string) {
	if len(params) != 1 {
		s.numericReply(c, ERR_NEEDMOREPARAMS, "WALLOPS")
		return
	}

	for _, v := range s.clients {
		if v.Is(client.Wallops) {
			v.Write(fmt.Sprintf("%s WALLOPS %s", s.listener.Addr(), params[1]))
		}
	}
}

func (s *Server) executeMessage(m *msg.Message, c *client.Client) {
	// ignore unregistered user commands until registration completes
	if !c.Registered && (m.Command != "CAP" && m.Command != "NICK" && m.Command != "USER" && m.Command != "PASS") {
		return
	}

	if e, ok := commandMap[strings.ToUpper(m.Command)]; ok {
		e(s, c, m.Parameters()...)
	} else {
		s.numericReply(c, ERR_UNKNOWNCOMMAND, m.Command)
	}
}

// determine if the given string is a channel
func isChannel(s string) bool {
	return s[0] == byte(channel.Remote) || s[0] == byte(channel.Local)
}
