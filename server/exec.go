package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mitchr/gossip/capability"
	cap "github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/mode"
	"github.com/mitchr/gossip/scan/msg"
	"github.com/mitchr/gossip/scan/wild"
	"golang.org/x/crypto/bcrypt"
)

type executor func(*Server, *client.Client, *msg.Message)

var commands = map[string]executor{
	// registration
	"PASS":         PASS,
	"NICK":         NICK,
	"USER":         USER,
	"OPER":         OPER,
	"QUIT":         QUIT,
	"CAP":          CAP,
	"AUTHENTICATE": AUTHENTICATE,
	"REGISTER":     REGISTER,
	"SETNAME":      SETNAME,
	"CHGHOST":      CHGHOST,

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
	"INFO":   INFO,

	// user queries
	"WHO":    WHO,
	"WHOIS":  WHOIS,
	"WHOWAS": WHOWAS,

	// communication
	"PRIVMSG": PRIVMSG,
	"NOTICE":  NOTICE,
	"TAGMSG":  TAGMSG,

	// miscellaneous
	"PING":    PING,
	"PONG":    PONG,
	"WALLOPS": WALLOPS,
	"ERROR":   ERROR,

	"AWAY":     AWAY,
	"REHASH":   REHASH,
	"USERHOST": USERHOST,
	"MONITOR":  MONITOR,
}

func PASS(s *Server, c *client.Client, m *msg.Message) {
	if c.Is(client.Registered) {
		s.writeReply(c, ERR_ALREADYREGISTRED)
		return
	} else if len(m.Params) != 1 {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "PASS")
		return
	}

	c.ServerPassAttempt = []byte(m.Params[0])
}

func NICK(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, ERR_NONICKNAMEGIVEN)
		return
	}

	nick := m.Params[0]
	if !validateNick(nick) {
		s.writeReply(c, ERR_ERRONEUSNICKNAME)
		return
	}

	if nick == c.Nick {
		// trying to change nick to what it already is; a no-op
		return
	}

	// if nickname is already in use, send back error
	if _, ok := s.getClient(nick); ok {
		if strings.ToLower(nick) == strings.ToLower(c.Nick) {
			// client could just be changing the case of their nick, which is ok
		} else {
			s.writeReply(c, ERR_NICKNAMEINUSE, nick)
			return
		}
	}

	// nick has been set previously
	if c.Nick != "" {
		// give back NICK to the caller and notify all the channels this
		// user is part of that their nick changed
		c.WriteMessage(msg.New(nil, c.String(), "", "", "NICK", []string{nick}, true))
		for _, v := range s.channelsOf(c) {
			v.ForAllMembersExcept(c, func(m *channel.Member) {
				m.WriteMessage(msg.New(nil, c.String(), "", "", "NICK", []string{nick}, true))
				m.Flush()
			})

			// update member map entry
			defer func(v *channel.Channel, oldNick string) {
				m, _ := v.GetMember(oldNick)
				v.DeleteMember(oldNick)
				v.SetMember(m)
			}(v, c.Nick)
		}

		// update client map entry
		s.deleteClient(c.Nick)
		c.Nick = nick
		s.setClient(c)
	} else { // nick is being set for first time
		c.Nick = nick
		s.endRegistration(c)
	}
}

func validateNick(s string) bool {
	if len(s) == 0 {
		return false
	}

	if isDisallowedNickStartChar(rune(s[0])) {
		return false
	}

	for _, v := range s[1:] {
		if isDisallowedNickChar(v) {
			return false
		}
	}
	return true
}

func isDisallowedNickStartChar(r rune) bool {
	return r == '$' || r == ':' || r == '#' || r == '&' || isDisallowedNickChar(r)
}

func isDisallowedNickChar(r rune) bool {
	return r == ' ' || r == ',' || r == '*' || r == '?' || r == '!' || r == '@' || r == '.'
}

func USER(s *Server, c *client.Client, m *msg.Message) {
	if c.Is(client.Registered) {
		s.writeReply(c, ERR_ALREADYREGISTRED)
		return
	} else if len(m.Params) < 4 || m.Params[3] == "" {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "USER")
		return
	}

	modeBits, err := strconv.Atoi(m.Params[1])
	if err == nil {
		// only allow user to make themselves invis or wallops
		c.SetMode(client.Mode(modeBits) & (client.Invisible | client.Wallops))
	}

	c.User = m.Params[0]
	c.Realname = m.Params[3]
	s.endRegistration(c)
}

func OPER(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 2 {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "OPER")
		return
	}

	name := m.Params[0]
	pass := m.Params[1]

	// will fail if username doesn't exist or if pass is incorrect
	if bcrypt.CompareHashAndPassword(s.Ops[name], []byte(pass)) != nil {
		s.writeReply(c, ERR_PASSWDMISMATCH)
		return
	}

	c.SetMode(client.Op)
	s.writeReply(c, RPL_YOUREOPER)
	c.WriteMessage(msg.New(nil, s.Name, "", "", "MODE", []string{c.Nick, "+o"}, false))
}

func QUIT(s *Server, c *client.Client, m *msg.Message) {
	reason := c.Nick + " quit" // assume client does not send a reason for quit
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
		if v.Len() == 1 {
			s.deleteChannel(v.String())
		} else {
			// message entire channel that client left
			v.DeleteMember(c.Nick)
			v.WriteMessage(msg.New(nil, c.String(), "", "", "QUIT", []string{reason}, true))
		}
	}

	s.ERROR(c, reason)
	s.deleteClient(c.Nick)
}

func (s *Server) endRegistration(c *client.Client) {
	if c.RegSuspended {
		return
	}
	if c.Nick == "" || c.User == "" { // tried to end without sending NICK & USER
		return
	}

	// client tried to finish registration with the nick of an already registered account
	if authn := s.userAccountForNickExists(c.Nick); authn != "" && c.SASLMech.Authn() != authn {
		s.writeReply(c, ERR_NICKNAMEINUSE, c.Nick)
		return
	}

	// we need this check here for the following situation: 1->NICK n;
	// 2->NICK n; 1-> USER u s e r; and then 2 tries to send USER, we
	// should reject 2's registration for having the same nick
	if _, ok := s.getClient(c.Nick); ok {
		s.writeReply(c, ERR_NICKNAMEINUSE, c.Nick)
		return
	}

	if s.Password != nil {
		if bcrypt.CompareHashAndPassword(s.Password, c.ServerPassAttempt) != nil {
			s.writeReply(c, ERR_PASSWDMISMATCH)
			s.ERROR(c, "Closing Link: "+s.Name+" (Bad Password)")
			return
		}
	}

	c.SetMode(client.Registered)
	s.setClient(c)
	s.unknowns.Dec()
	s.max.KeepMax(uint(s.clientLen()))

	// send RPL_WELCOME and friends in acceptance
	s.writeReply(c, RPL_WELCOME, s.Network, c)
	s.writeReply(c, RPL_YOURHOST, s.Name)
	s.writeReply(c, RPL_CREATED, s.created)
	// serverName, version, userModes, chanModes
	s.writeReply(c, RPL_MYINFO, s.Name, "0", "ioOrw", "beliIkmstn")
	for _, support := range isupportTokens {
		s.writeReply(c, RPL_ISUPPORT, support)
	}

	LUSERS(s, c, nil)
	MOTD(s, c, nil)

	// after registration burst, give clients max grants
	c.FillGrants()

	s.notifyOn(c)
}

func SETNAME(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.stdReply(c, FAIL, "SETNAME", "INVALID_REALNAME", "", "Realname cannot be empty")
		return
	}

	c.Realname = m.Params[0]

	// "If a client sends a SETNAME command without having negotiated the
	// capability, the server SHOULD handle it silently (with no
	// response), as historic implementations did."
	if _, verbose := c.Caps[cap.Setname.Name]; !verbose {
		return
	}

	chans := s.channelsOf(c)
	for _, v := range chans {
		v.ForAllMembersExcept(c, func(m *channel.Member) {
			if !m.Caps[cap.Setname.Name] {
				return
			}
			m.WriteMessage(msg.New(nil, c.String(), "", "", "SETNAME", []string{c.Realname}, true))
			m.Flush()
		})
	}
	c.WriteMessage(msg.New(nil, c.String(), "", "", "SETNAME", []string{c.Realname}, true))
}

func CHGHOST(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 2 {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "CHGHOST")
		return
	}

	oldPrefix := c.String()

	c.User = m.Params[0]
	c.Host = m.Params[1]

	chans := s.channelsOf(c)
	for _, v := range chans {
		member, _ := v.GetMember(c.Nick)
		modes := member.ModeLetters()

		v.ForAllMembersExcept(c, func(m *channel.Member) {
			if m.Caps[cap.Chghost.Name] {
				m.WriteMessage(msg.New(nil, oldPrefix, "", "", "CHGHOST", []string{c.User, c.Host}, false))
			} else {
				m.WriteMessage(msg.New(nil, oldPrefix, "", "", "QUIT", []string{"Changing hostname"}, true))
				m.WriteMessage(msg.New(nil, c.String(), "", "", "JOIN", []string{v.String()}, false))
				if modes != "" {
					m.WriteMessage(msg.New(nil, s.Name, "", "", "MODE", []string{v.String(), "+" + modes, c.Nick}, false))
				}
			}
			m.Flush()
		})
	}

	// "send the CHGHOST message to the client whose own username or host
	// changed, if that client also supports the chghost capability"
	if _, verbose := c.Caps[cap.Chghost.Name]; verbose {
		c.WriteMessage(msg.New(nil, oldPrefix, "", "", "CHGHOST", []string{c.User, c.Host}, false))
	}
}

func JOIN(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "JOIN")
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

	s.joinLock.Lock()
	defer s.joinLock.Unlock()

	for i := range chans {
		if ch, ok := s.getChannel(chans[i]); ok { // channel already exists
			err := ch.Admit(c, keys[i])
			if err != nil {
				if err == channel.ErrKeyMissing {
					s.writeReply(c, ERR_BADCHANNELKEY, ch)
				} else if err == channel.ErrLimitReached { // not aceepting new clients
					s.writeReply(c, ERR_CHANNELISFULL, ch)
				} else if err == channel.ErrNotInvited {
					s.writeReply(c, ERR_INVITEONLYCHAN, ch)
				} else if err == channel.ErrBanned { // client is banned
					s.writeReply(c, ERR_BANNEDFROMCHAN, ch)
				}
				return
			}

			// send JOIN to all participants of channel
			joinMsgParams := []string{ch.String(), c.SASLMech.Authn(), c.Realname}
			ch.MembersLock.Lock()
			for _, m := range ch.Members {
				joinMsg := msg.New(nil, c.Nick, c.User, c.Host, "JOIN", nil, false)
				if m.Caps[capability.ExtendedJoin.Name] {
					joinMsg.Params = joinMsgParams
				} else {
					joinMsg.Params = joinMsgParams[:1]
				}
				m.WriteMessage(joinMsg)
				m.Flush()
			}
			ch.MembersLock.Unlock()

			if ch.Topic != "" {
				// only send topic if it exists
				TOPIC(s, c, &msg.Message{Params: []string{ch.String()}})
			}
			NAMES(s, c, &msg.Message{Params: []string{ch.String()}})
			s.awayNotify(c, ch)
		} else { // create new channel
			chanChar := channel.ChanType(chans[i][0])
			chanName := chans[i][1:]

			if !isValidChannelString(string(chanChar) + chanName) {
				s.writeReply(c, ERR_NOSUCHCHANNEL, chans[i])
				return
			}

			newChan := channel.New(chanName, chanChar)
			s.setChannel(newChan)
			newChan.SetMember(&channel.Member{Client: c, Prefix: string(channel.Founder)})
			c.WriteMessage(msg.New(nil, c.String(), "", "", "JOIN", []string{newChan.String()}, false))

			NAMES(s, c, &msg.Message{Params: []string{newChan.String()}})
		}
	}
}

func isValidChannelString(ch string) bool {
	if len(ch) == 0 {
		return false
	}

	if ch[0] != byte(channel.Remote) && ch[0] != byte(channel.Local) {
		return false
	}

	for _, v := range ch {
		if isDisallowedChanChar(rune(v)) {
			return false
		}
	}
	return true
}

func isDisallowedChanChar(r rune) bool {
	return r == 0x20 || r == 0x07 || r == 0x2c
}

func PART(s *Server, c *client.Client, m *msg.Message) {
	chans := strings.Split(m.Params[0], ",")

	params := make([]string, 1)
	if len(m.Params) > 1 {
		params = append(params, m.Params[1])
	}

	for _, v := range chans {
		ch := s.clientBelongstoChan(c, v)
		if ch == nil {
			return
		}

		params[0] = ch.String()
		ch.WriteMessage(msg.New(nil, c.String(), "", "", "PART", params, len(params) > 1))

		if ch.Len() == 1 {
			s.deleteChannel(ch.String())
		} else {
			ch.DeleteMember(c.Nick)
		}
	}
}

func TOPIC(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "TOPIC")
		return
	}

	ch := s.clientBelongstoChan(c, m.Params[0])
	if ch == nil {
		return
	}

	if len(m.Params) >= 2 { // modify topic
		if m, _ := ch.GetMember(c.Nick); ch.Protected && !m.Is(channel.Operator) {
			s.writeReply(c, ERR_CHANOPRIVSNEEDED, ch)
			return
		}
		ch.Topic = m.Params[1]
		ch.TopicSetBy = c
		ch.TopicSetAt = time.Now()
		ch.WriteMessage(msg.New(nil, s.Name, "", "", "TOPIC", []string{ch.String(), ch.Topic}, true))
	} else {
		if ch.Topic == "" {
			s.writeReply(c, RPL_NOTOPIC, ch)
		} else { // give back existing topic
			s.writeReply(c, RPL_TOPIC, ch, ch.Topic)
			s.writeReply(c, RPL_TOPICWHOTIME, ch, ch.TopicSetBy, ch.TopicSetAt.Unix())
		}
	}
}

func INVITE(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 2 {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "INVITE")
		return
	}

	nick := m.Params[0]
	ch, ok := s.getChannel(m.Params[1])
	if !ok { // channel does not exist
		s.writeReply(c, ERR_NOSUCHCHANNEL, m.Params[1])
		return
	}

	sender, _ := ch.GetMember(c.Nick)
	recipient, _ := s.getClient(nick)
	if sender == nil { // only members can invite
		s.writeReply(c, ERR_NOTONCHANNEL, ch)
		return
	} else if ch.Invite && !sender.Is(channel.Operator) { // if invite mode set, only ops can send an invite
		s.writeReply(c, ERR_CHANOPRIVSNEEDED, ch)
		return
	} else if recipient == nil { // nick not on server
		s.writeReply(c, ERR_NOSUCHNICK, nick)
		return
	} else if _, ok := ch.GetMember(nick); ok { // can't invite a member who is already on channel
		s.writeReply(c, ERR_USERONCHANNEL, nick, ch)
		return
	}

	ch.Invited = append(ch.Invited, nick)

	recipient.WriteMessageFrom(msg.New(nil, sender.Nick, sender.User, sender.Host, "INVITE", []string{nick, ch.String()}, false), c)
	recipient.Flush()

	s.writeReply(c, RPL_INVITING, nick, ch)
}

// if c belongs to the channel associated with chanName, return that
// channel. If it doesn't, or if the channel doesn't exist, write a
// numeric reply to the client and return nil.
func (s *Server) clientBelongstoChan(c *client.Client, chanName string) *channel.Channel {
	ch, ok := s.getChannel(chanName)
	if !ok { // channel not found
		s.writeReply(c, ERR_NOSUCHCHANNEL, chanName)
	} else {
		if _, ok := ch.GetMember(c.Nick); !ok { // client does not belong to channel
			s.writeReply(c, ERR_NOTONCHANNEL, ch)
		}
	}
	return ch
}

func KICK(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 2 {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "KICK")
		return
	}

	comment := c.Nick
	if len(m.Params) == 3 {
		comment = m.Params[2]
	}

	chans := strings.Split(m.Params[0], ",")
	users := strings.Split(m.Params[1], ",")
	if len(chans) != 1 || len(chans) != len(users) {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "KICK")
		return
	}

	for i, v := range chans {
		ch, _ := s.getChannel(v)
		if ch == nil {
			s.writeReply(c, ERR_NOSUCHCHANNEL, v)
			return
		}
		self, _ := ch.GetMember(c.Nick)
		if self == nil {
			s.writeReply(c, ERR_NOTONCHANNEL, ch)
			return
		} else if !self.Is(channel.Operator) {
			s.writeReply(c, ERR_CHANOPRIVSNEEDED, ch)
			return
		}

		// If there are multiple channels, pair up the chans and users so
		// that one user is kicked per each chan
		if len(chans) != 1 {
			s.kickMember(c, ch, users[i], comment)
		} else {
			// If we are only given one channel, kick all listed users from it
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
		s.writeReply(c, ERR_USERNOTINCHANNEL, memberNick, ch)
		return
	}

	// send KICK to all channel members but self
	ch.ForAllMembersExcept(c, func(m *channel.Member) {
		m.WriteMessageFrom(msg.New(nil, c.Nick, c.User, c.Host, "KICK", []string{ch.String(), u.Nick, comment}, true), c)
		m.Flush()
	})

	ch.DeleteMember(u.Nick)
}

func NAMES(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) == 0 {
		s.writeReply(c, RPL_ENDOFNAMES, "*")
		return
	}

	chans := strings.Split(m.Params[0], ",")
	for _, v := range chans {
		ch, _ := s.getChannel(v)
		if ch == nil {
			s.writeReply(c, RPL_ENDOFNAMES, v)
		} else {
			_, ok := ch.GetMember(c.Nick)
			if ch.Secret && !ok { // chan is secret and client does not belong
				s.writeReply(c, RPL_ENDOFNAMES, v)
			} else {
				sym, members := constructNAMREPLY(ch, ok, c.Caps[cap.MultiPrefix.Name], c.Caps[cap.UserhostInNames.Name])
				s.writeReply(c, RPL_NAMREPLY, sym, ch, members)
				s.writeReply(c, RPL_ENDOFNAMES, v)
			}
		}
	}
}

func LIST(s *Server, c *client.Client, m *msg.Message) {
	defer s.writeReply(c, RPL_LISTEND)

	if len(m.Params) == 0 {
		// reply with all channels that aren't secret
		s.chanLock.RLock()
		for _, v := range s.channels {
			s.sendListReply(v, c)
		}
		s.chanLock.RUnlock()
		return
	}

	var chans, elist []string
	chans = strings.Split(m.Params[0], ",")
	if len(m.Params) == 2 {
		elist = strings.Split(m.Params[1], ",")
	}

	// the first param could be a list of channels or elist conditions. we
	// can assume they are elist conditions, which means we filter over
	// all channels. if they do indeed end up just being channel strings,
	// they will be caught in the default mask match (which will only be
	// an O(1) lookup)
	if elist == nil {
		elist = chans
		chans = make([]string, s.channelLen())
		i := 0
		s.chanLock.RLock()
		for _, v := range s.channels {
			chans[i] = v.String()
			i++
		}
		s.chanLock.RUnlock()
	}

	replies := []*channel.Channel{}
	for _, v := range chans {
		if ch, ok := s.getChannel(v); ok {
			replies = append(replies, ch)
		}
	}

	for _, v := range elist {
		replies = s.applyElistConditions(v, replies)
	}

	for _, v := range replies {
		s.sendListReply(v, c)
	}
}

func (s *Server) applyElistConditions(pattern string, chans []*channel.Channel) []*channel.Channel {
	filtered := []*channel.Channel{}

	switch pattern[0] {
	case '<', '>':
		lessThan := pattern[0] == '<'
		val, _ := strconv.Atoi(pattern[1:])

		for _, v := range chans {
			userCount := v.Len()
			if (lessThan && userCount < val) || (!lessThan && userCount > val) {
				filtered = append(filtered, v)
			}
		}
	case 'C':
		lessThan := pattern[1] == '<'
		if len(pattern) < 2 {
			break
		}
		val, _ := strconv.Atoi(pattern[2:])
		valMinutes := time.Minute * time.Duration(val)

		for _, v := range chans {
			difference := time.Since(v.CreatedAt).Round(time.Minute)
			// topic time that was set less than val minutes ago OR
			// topic time that was set more than val minutes ago
			if (lessThan && difference < valMinutes) || (!lessThan && difference > valMinutes) {
				filtered = append(filtered, v)
			}
		}
	case 'T':
		lessThan := pattern[1] == '<'
		if len(pattern) < 2 {
			break
		}
		val, _ := strconv.Atoi(pattern[2:])
		valMinutes := time.Minute * time.Duration(val)

		for _, v := range chans {
			difference := time.Since(v.TopicSetAt).Round(time.Minute)
			// topic time that was set less than val minutes ago OR
			// topic time that was set more than val minutes ago
			if (lessThan && difference < valMinutes) || (!lessThan && difference > valMinutes) {
				filtered = append(filtered, v)
			}
		}
	case '!':
		for _, v := range chans {
			if !wild.Match(pattern[1:], v.String()) {
				filtered = append(filtered, v)
			}
		}
	default:
		// first see if we can get an exact match
		if ch, ok := s.getChannel(pattern); ok {
			filtered = append(filtered, ch)
		} else {
			for _, v := range chans {
				if wild.Match(pattern, v.String()) {
					filtered = append(filtered, v)
				}
			}
		}
	}
	return filtered
}

func (s *Server) sendListReply(ch *channel.Channel, c *client.Client) {
	_, ok := ch.GetMember(c.Nick)
	// skip sending reply for secret channel unless this client is a
	// member of that channel
	if ch.Secret && !ok {
		return
	}
	s.writeReply(c, RPL_LIST, ch, ch.Len(), ch.Topic)
}

func MOTD(s *Server, c *client.Client, m *msg.Message) {
	if len(s.motd) == 0 {
		s.writeReply(c, ERR_NOMOTD)
		return
	}

	s.writeReply(c, RPL_MOTDSTART, s.Name)
	for _, v := range s.motd {
		s.writeReply(c, RPL_MOTD, v)
	}
	s.writeReply(c, RPL_ENDOFMOTD)
}

func LUSERS(s *Server, c *client.Client, m *msg.Message) {
	invis := 0
	ops := 0
	clientSize := s.clientLen()
	max := s.max.Get()

	s.clientLock.RLock()
	for _, v := range s.clients {
		if v.Is(client.Invisible) {
			invis++
			continue
		}
		if v.Is(client.Op) {
			ops++
		}
	}
	s.clientLock.RUnlock()

	s.writeReply(c, RPL_LUSERCLIENT, clientSize, invis, 1)
	s.writeReply(c, RPL_LUSEROP, ops)
	s.writeReply(c, RPL_LUSERUNKNOWN, s.unknowns.Get())
	s.writeReply(c, RPL_LUSERCHANNELS, s.channelLen())
	s.writeReply(c, RPL_LUSERME, clientSize, 1)
	s.writeReply(c, RPL_LOCALUSERS, clientSize, max, clientSize, max)
	s.writeReply(c, RPL_GLOBALUSERS, clientSize, max, clientSize, max)
}

func TIME(s *Server, c *client.Client, m *msg.Message) {
	s.writeReply(c, RPL_TIME, s.Name, time.Now().Local())
}

// TODO: support commands like this that intersperse the modechar and modem.Params MODE &oulu +b *!*@*.edu +e *!*@*.bu.edu
func MODE(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 { // give back own mode
		s.writeReply(c, RPL_UMODEIS, c.Mode)
		return
	}

	target := m.Params[0]
	if !isValidChannelString(target) {
		client, ok := s.getClient(target)
		if !ok {
			s.writeReply(c, ERR_NOSUCHNICK, target)
			return
		}
		if client.Nick != c.Nick { // can't modify another user
			s.writeReply(c, ERR_USERSDONTMATCH)
			return
		}

		if len(m.Params) == 2 { // modify own mode
			appliedModes := []mode.Mode{}
			for _, v := range mode.Parse([]byte(m.Params[1])) {
				found := c.ApplyMode(v)
				if !found {
					s.writeReply(c, ERR_UMODEUNKNOWNFLAG)
				} else {
					appliedModes = append(appliedModes, v)
				}
			}

			modeStr := buildModestr(appliedModes)
			c.WriteMessage(msg.New(nil, s.Name, "", "", "MODE", []string{c.Nick, modeStr}, false))
		} else { // give back own mode
			s.writeReply(c, RPL_UMODEIS, c.Mode)
		}
	} else {
		ch, ok := s.getChannel(target)
		if !ok {
			s.writeReply(c, ERR_NOSUCHCHANNEL, target)
			return
		}

		if len(m.Params) == 1 { // modeStr not given, give back channel modes
			modeStr, params := ch.Modes()
			if len(params) != 0 {
				modeStr += " "
			}

			s.writeReply(c, RPL_CHANNELMODEIS, ch, modeStr, strings.Join(params, " "))
			s.writeReply(c, RPL_CREATIONTIME, ch, ch.CreatedAt)
		} else { // modeStr given
			modes := mode.Parse([]byte(m.Params[1]))
			channel.PrepareModes(modes, m.Params[2:])
			appliedModes := []mode.Mode{}
			for _, m := range modes {
				if m.Type == mode.List {
					switch m.ModeChar {
					case 'b':
						s.sendChannelModeList(c, ch, ch.Ban, RPL_BANLIST, RPL_ENDOFBANLIST)
					case 'e':
						s.sendChannelModeList(c, ch, ch.BanExcept, RPL_EXCEPTLIST, RPL_ENDOFEXCEPTLIST)
					case 'I':
						s.sendChannelModeList(c, ch, ch.InviteExcept, RPL_INVITELIST, RPL_ENDOFINVITELIST)
					}
					continue
				}
				err := ch.ApplyMode(m)
				if errors.Is(err, channel.ErrNeedMoreParams) {
					s.writeReply(c, ERR_NEEDMOREPARAMS, err)
				} else if errors.Is(err, channel.ErrUnknownMode) {
					s.writeReply(c, ERR_UNKNOWNMODE, err, ch)
				} else if errors.Is(err, channel.ErrNotInChan) {
					s.writeReply(c, ERR_USERNOTINCHANNEL, err, ch)
				} else if errors.Is(err, channel.ErrInvalidKey) {
					s.writeReply(c, ERR_INVALIDKEY, ch)
				} else {
					appliedModes = append(appliedModes, m)
				}
			}

			modeStr := buildModestr(appliedModes)

			// only write final MODE to channel if any mode was actually altered
			if modeStr != "" {
				ch.WriteMessageFrom(msg.New(nil, s.Name, "", "", "MODE", []string{ch.String(), modeStr}, false), c)
			}
		}
	}
}

func buildModestr(modes []mode.Mode) string {
	applied := []rune{}
	removed := []rune{}
	params := []string{}
	for _, m := range modes {
		if m.Param != "" {
			params = append(params, m.Param)
		}
		if m.Type == mode.Add {
			applied = append(applied, m.ModeChar)
		} else if m.Type == mode.Remove {
			removed = append(removed, m.ModeChar)
		}
	}

	var modeStr string
	if len(applied) > 0 {
		modeStr += "+" + string(applied)
	}
	if len(removed) > 0 {
		modeStr += "-" + string(removed)
	}

	params = append([]string{modeStr}, params...)
	return strings.Join(params, " ")
}

// used for responding to requests to list the various channel mode lists
func (s *Server) sendChannelModeList(c *client.Client, ch *channel.Channel, list []string, dataResponse string, endResponse string) {
	for _, v := range list {
		s.writeReply(c, dataResponse, ch, v)
	}
	s.writeReply(c, endResponse, ch)
}

func INFO(s *Server, c *client.Client, m *msg.Message) {
	s.writeReply(c, RPL_INFO, "gossip is licensed under GPLv3")
	s.writeReply(c, RPL_ENDOFINFO)
}

func WHO(s *Server, c *client.Client, m *msg.Message) {
	mask := "*"
	if len(m.Params) > 0 {
		if mask == "0" {
			mask = "*"
		} else {
			mask = strings.ToLower(m.Params[0])
		}
	}

	whox := len(m.Params) > 1
	var fields string
	if whox {
		fields = m.Params[1]
	}

	// first, try to match channels exactly against the mask. if exists,
	// returns WHOREPLY for every member in channel. else, we will match
	// exactly against the client name.
	ch, ok := s.getChannel(mask)
	if ok {
		ch.MembersLock.RLock()
		for _, member := range ch.Members {
			if whox {
				resp := constructSpcrplResponse(fields, member.Client, s)
				s.writeReply(c, RPL_WHOSPCRPL, resp)
			} else {
				flags := whoreplyFlagsForMember(member, c.Caps[cap.MultiPrefix.Name])
				s.writeReply(c, RPL_WHOREPLY, ch, member.User, member.Host, s.Name, member.Nick, flags, member.Realname)
			}
		}
		ch.MembersLock.RUnlock()
		s.writeReply(c, RPL_ENDOFWHO, mask)
		return
	}

	// no channel results found, match against a single client
	whoClient, ok := s.getClient(mask)
	if ok {
		if whox {
			resp := constructSpcrplResponse(fields, whoClient, s)
			s.writeReply(c, RPL_WHOSPCRPL, resp)
		} else {
			flags := whoreplyFlagsForClient(whoClient)
			s.writeReply(c, RPL_WHOREPLY, "*", whoClient.User, whoClient.Host, s.Name, whoClient.Nick, flags, whoClient.Realname)
		}
		s.writeReply(c, RPL_ENDOFWHO, mask)
		return
	}

	// no exact client matches, so use mask to match against all visible clients
	onlyOps := len(m.Params) > 1 && m.Params[1] == "o"
	s.clientLock.RLock()
	for _, v := range s.clients {
		if onlyOps && !v.Is(client.Op) { // skip this client if they are not an op
			continue
		}

		// "Visible users are users who aren’t invisible (user mode +i) and
		// who don’t have a common channel with the requesting client"
		// https://modern.ircdocs.horse/#who-message
		if v.Is(client.Invisible) && !s.haveChanInCommon(c, v) {
			continue
		}

		if wild.Match(mask, strings.ToLower(v.Nick)) {
			if whox {
				resp := constructSpcrplResponse(fields, v, s)
				s.writeReply(c, RPL_WHOSPCRPL, resp)
			} else {
				flags := whoreplyFlagsForClient(v)
				s.writeReply(c, RPL_WHOREPLY, "*", v.User, v.Host, s.Name, v.Nick, flags, v.Realname)
			}
		}
	}
	s.clientLock.RUnlock()
	s.writeReply(c, RPL_ENDOFWHO, mask)
}

var whoxTokenHierarchy = map[byte]int{
	't': 1,
	'c': 2,
	'u': 3,
	'i': 4,
	'h': 5,
	's': 6,
	'n': 7,
	'f': 8,
	'd': 9,
	'l': 10,
	'a': 11,
	'o': 12,
	'r': 13,
}

// construct params used in whox reply
func constructSpcrplResponse(params string, c *client.Client, s *Server) string {
	split := strings.Split(params, ",")
	fields := []byte(split[0][1:]) // trim beginning '%'

	// sort the tokens so they are in the correct response order
	sort.Slice(fields, func(i, j int) bool {
		return whoxTokenHierarchy[fields[i]] < whoxTokenHierarchy[fields[j]]
	})
	resp := make([]string, len(fields))

	var chanRef *channel.Channel

	for i, f := range fields {
		switch f {
		case 't':
			if len(split) > 1 {
				resp[i] = split[1]
			}
		case 'c':
			channel := "*"
			chans := s.channelsOf(c)
			if len(chans) > 0 {
				chanRef = chans[0]
				channel = chans[0].String()
			}
			resp[i] = channel
		case 'u':
			resp[i] = c.User
		case 'i':
			// TODO: will this assertion fail if we add support for websockets?
			resp[i] = c.RemoteAddr().(*net.TCPAddr).IP.String()
		case 'h':
			resp[i] = c.Host
		case 's':
			resp[i] = s.Name
		case 'n':
			resp[i] = c.Nick
		case 'f':
			flags := whoreplyFlagsForClient(c)
			resp[i] = flags
		case 'd':
			resp[i] = "0"
		case 'l':
			resp[i] = fmt.Sprintf("%v", time.Since(c.Idle).Round(time.Second).Seconds())
		case 'a':
			a := "0"
			if c.IsAuthenticated {
				a = c.SASLMech.Authn()
			}
			resp[i] = a
		case 'o':
			prefix := "n/a"
			if chanRef != nil {
				m, _ := chanRef.GetMember(c.Nick)
				if m.Is(channel.Operator) {
					prefix = string(channel.Operator)
				} else if m.Is(channel.Halfop) {
					prefix = string(channel.Halfop)
				} else if m.Is(channel.Founder) {
					prefix = string(channel.Founder)
				}
			}
			resp[i] = prefix
		case 'r':
			resp[i] = ":" + c.Realname
		}
	}

	return strings.Join(resp, " ")
}

// we only support the <mask> *( "," <mask> ) parameter, target seems
// pointless with only one server in the tree
func WHOIS(s *Server, c *client.Client, m *msg.Message) {
	// silently ignore empty m.Params
	if len(m.Params) < 1 {
		return
	}

	// ignore optional target param
	nicks := m.Params[0]
	if len(m.Params) == 2 {
		nicks = m.Params[1]
	}

	masks := strings.Split(strings.ToLower(nicks), ",")
	for _, m := range masks {
		if v, ok := s.getClient(m); ok {
			s.sendWHOIS(c, v)
			continue
		}

		s.clientLock.RLock()
		for _, v := range s.clients {
			if wild.Match(m, v.Nick) {
				s.sendWHOIS(c, v)
			}
		}
		s.clientLock.RUnlock()
	}

	s.writeReply(c, RPL_ENDOFWHOIS, m.Params[0])
}

func (s *Server) sendWHOIS(c *client.Client, v *client.Client) {
	if v.Is(client.Away) {
		s.writeReply(c, RPL_AWAY, v.Nick, v.AwayMsg)
	}

	s.writeReply(c, RPL_WHOISUSER, v.Nick, v.User, v.Host, v.Realname)
	s.writeReply(c, RPL_WHOISSERVER, v.Nick, s.Name, "wip irc server")
	if v.Is(client.Bot) {
		s.writeReply(c, RPL_WHOISBOT, v.Nick)
	}
	if v.Is(client.Op) {
		s.writeReply(c, RPL_WHOISOPERATOR, v.Nick)
	}
	if v == c || c.Is(client.Op) { // querying whois on self or self is an op
		if v.IsSecure() {
			certPrint, err := v.CertificateFingerprint()
			if err == nil {
				s.writeReply(c, RPL_WHOISCERTFP, v.Nick, certPrint)
			}
		}
	}
	s.writeReply(c, RPL_WHOISIDLE, v.Nick, time.Since(v.Idle).Round(time.Second).Seconds(), v.JoinTime)

	chans := []string{}
	s.chanLock.RLock()
	for _, k := range s.channels {
		_, senderBelongs := k.GetMember(c.Nick)
		member, clientBelongs := k.GetMember(v.Nick)

		// if client is invisible or this channel is secret, only send
		// a response if the sender shares a channel with this client
		if (k.Secret || v.Is(client.Invisible)) && !(senderBelongs && clientBelongs) {
			continue
		}
		hasMultiPrefix := c.Caps[cap.MultiPrefix.Name]
		chans = append(chans, string(member.HighestPrefix(hasMultiPrefix))+k.String())
	}
	s.chanLock.RUnlock()

	chanParam := ""
	if len(chans) > 0 {
		chanParam = " :" + strings.Join(chans, " ")
	}
	s.writeReply(c, RPL_WHOISCHANNELS, v.Nick, chanParam)

	if v.IsAuthenticated {
		s.writeReply(c, RPL_WHOISACCOUNT, v.Nick, v.SASLMech.Authn())
	}
}

func WHOWAS(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, ERR_NONICKNAMEGIVEN)
		return
	}

	count := s.whowasHistory.len()
	if len(m.Params) > 1 {
		givenCount, _ := strconv.Atoi(m.Params[1])
		// negative counts should be treated as wanting to traverse the entire history
		if givenCount > 0 {
			count = givenCount
		}
	}

	nicks := strings.Split(m.Params[0], ",")
	for _, nick := range nicks {
		info := s.whowasHistory.search(nick, count)
		if len(info) == 0 {
			s.writeReply(c, ERR_WASNOSUCHNICK, nick)
			s.writeReply(c, RPL_ENDOFWHOWAS, nick)
			continue
		}

		for _, v := range info {
			s.writeReply(c, RPL_WHOWASUSER, v.nick, v.user, v.host, v.realname)
		}
		s.writeReply(c, RPL_ENDOFWHOWAS, nick)
	}
}

func PRIVMSG(s *Server, c *client.Client, m *msg.Message) { s.communicate(m, c) }
func NOTICE(s *Server, c *client.Client, m *msg.Message)  { s.communicate(m, c) }

// communicate is used for PRIVMSG/NOTICE
func (s *Server) communicate(m *msg.Message, c *client.Client) {
	msg := *m
	// "Tags without the client-only prefix MUST be removed by the
	// server before being relayed with any message to another client."
	msg.TrimNonClientTags()
	msg.Nick = c.Nick
	msg.Host = c.Host
	msg.User = c.User

	skipReplies := m.Command == "NOTICE" || m.Command == "TAGMSG"

	if len(m.Params) < 2 && m.Command != "TAGMSG" {
		if !skipReplies {
			s.writeReply(c, ERR_NOTEXTTOSEND)
		}
		return
	}

	recipients := strings.Split(m.Params[0], ",")
	for _, v := range recipients {
		msg.Params[0] = v

		// TODO: support sending to only a specific user mode in channel (i.e., PRIVMSG %#buffy)
		if isValidChannelString(v) {
			ch, _ := s.getChannel(v)
			if ch == nil { // channel doesn't exist
				if !skipReplies {
					s.writeReply(c, ERR_NOSUCHCHANNEL, v)
				}
				continue
			}

			self, _ := ch.GetMember(c.Nick)
			if self == nil {
				if ch.NoExternal {
					// chan does not allow external messages; client needs to join
					if !skipReplies {
						s.writeReply(c, ERR_CANNOTSENDTOCHAN, ch)
					}
					continue
				}
			} else if ch.Moderated && self.Prefix == "" {
				// member has no mode, so they cannot speak in a moderated chan
				if !skipReplies {
					s.writeReply(c, ERR_CANNOTSENDTOCHAN, ch)
				}
				continue
			}

			// write to everybody else in the chan besides self
			ch.ForAllMembersExcept(c, func(m *channel.Member) {
				if msg.Command == "TAGMSG" && !m.Caps[cap.MessageTags.Name] {
					return
				}
				if m.Caps[capability.MessageTags.Name] {
					msg.SetMsgid()
				}
				m.WriteMessageFrom(&msg, c)
				m.Flush()
			})
		} else { // client->client
			target, ok := s.getClient(v)
			if !ok {
				if !skipReplies {
					s.writeReply(c, ERR_NOSUCHNICK, v)
				}
				continue
			}

			if target.Is(client.Away) {
				s.writeReply(c, RPL_AWAY, target.Nick, target.AwayMsg)
				continue
			}
			if msg.Command == "TAGMSG" && !target.Caps[cap.MessageTags.Name] {
				continue
			}
			if target.Caps[capability.MessageTags.Name] {
				msg.SetMsgid()
			}
			target.WriteMessageFrom(&msg, c)
			target.Flush()
		}
	}

	if c.Caps[cap.EchoMessage.Name] {
		c.WriteMessage(&msg)
	}
}

func PING(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "PING")
		return
	}

	c.WriteMessage(msg.New(nil, s.Name, "", "", "PONG", []string{s.Name, m.Params[0]}, m.Params[0] == ""))
}

func PONG(s *Server, c *client.Client, m *msg.Message) {
	c.PONG <- struct{}{}
}

// this is currently a noop, as a server should only accept ERROR
// commands from other servers
func ERROR(s *Server, c *client.Client, m *msg.Message) {}

func AWAY(s *Server, c *client.Client, m *msg.Message) {
	defer s.awayNotify(c, s.channelsOf(c)...)

	// remove away
	if len(m.Params) == 0 {
		c.AwayMsg = ""
		c.UnsetMode(client.Away)
		s.writeReply(c, RPL_UNAWAY)
		return
	}

	c.AwayMsg = m.Params[0]
	c.SetMode(client.Away)
	s.writeReply(c, RPL_NOWAWAY)
}

func (s *Server) awayNotify(c *client.Client, chans ...*channel.Channel) {
	for _, v := range chans {
		v.ForAllMembersExcept(c, func(m *channel.Member) {
			if m.Caps[cap.AwayNotify.Name] {
				m.WriteMessage(msg.New(nil, c.String(), "", "", "AWAY", []string{c.AwayMsg}, true))
				m.Flush()
			}
		})
	}
}

func REHASH(s *Server, c *client.Client, m *msg.Message) {
	if !c.Is(client.Op) {
		s.writeReply(c, ERR_NOPRIVILEGES)
		return
	}

	conf, _ := NewConfig(s.configSource)
	s.Config = conf

	fileName := s.configSource.(*os.File).Name()
	s.writeReply(c, RPL_REHASHING, fileName)
}

func USERHOST(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "USERHOST")
		return
	}

	replies := make([]string, 0, len(m.Params))
	for _, nick := range m.Params {
		client, ok := s.getClient(nick)
		if ok {
			replies = append(replies, constructUserhostReply(client))
		}
	}
	s.writeReply(c, RPL_USERHOST, strings.Join(replies, " "))

}

func constructUserhostReply(c *client.Client) string {
	s := c.Nick
	if c.Is(client.Op) {
		s += "*"
	}
	s += "="
	if c.AwayMsg != "" {
		s += "-"
	} else {
		s += "+"
	}
	s += c.Host
	return s
}

func WALLOPS(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, ERR_NEEDMOREPARAMS, "WALLOPS")
		return
	}

	m.Nick = c.Nick
	m.User = c.User
	m.Host = c.Host

	s.clientLock.RLock()
	for _, v := range s.clients {
		if v.Is(client.Wallops) {
			v.WriteMessage(m)
			v.Flush()
		}
	}
	s.clientLock.RUnlock()
}

func (s *Server) executeMessage(m *msg.Message, c *client.Client) {
	upper := strings.ToUpper(m.Command)
	// ignore unregistered user commands until registration completes
	if !c.Is(client.Registered) && (upper != "CAP" && upper != "NICK" && upper != "USER" && upper != "PASS" && upper != "AUTHENTICATE" && upper != "QUIT" && upper != "PING") {
		s.writeReply(c, ERR_NOTREGISTERED)
		c.Flush()
		return
	}

	if e, ok := commands[upper]; ok {
		c.Idle = time.Now()
		e(s, c, m)
	} else {
		s.writeReply(c, ERR_UNKNOWNCOMMAND, m.Command)
	}
	c.Flush()
}
