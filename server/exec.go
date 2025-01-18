package server

import (
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	cap "github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/mode"
	"github.com/mitchr/gossip/scan/msg"
	"github.com/mitchr/gossip/scan/wild"
	"golang.org/x/crypto/bcrypt"
)

type executor func(*Server, *client.Client, *msg.Message) msg.Msg

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

func PASS(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if c.Is(client.Registered) {
		return prepMessage(ERR_ALREADYREGISTRED, s.Name, c.Id())
	} else if len(m.Params) != 1 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "PASS")
	}

	if s.Password != nil {
		if bcrypt.CompareHashAndPassword(s.Password, []byte(m.Params[0])) == nil {
			c.ServerPassAccepted = true
		}
	}

	return nil
}

func NICK(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 1 {
		return prepMessage(ERR_NONICKNAMEGIVEN, s.Name, c.Id())
	}

	nick := m.Params[0]
	if !validateNick(nick) {
		return prepMessage(ERR_ERRONEUSNICKNAME, s.Name, c.Id())
	}

	// trying to change nick to what it already is; a no-op
	if nick == c.Nick {
		return nil
	}

	changingCase := false

	// if nickname is already in use, send back error
	if _, ok := s.getClient(nick); ok {
		// client is changing the case of their nick
		if strings.ToLower(nick) == strings.ToLower(c.Nick) {
			changingCase = true
		} else if c.Is(client.Registered) {
			return prepMessage(ERR_NICKNAMEINUSE, s.Name, c.Id(), nick)
		}
	}

	// nick has been set previously
	if c.Nick != "" {
		// give back NICK to the caller and notify all the channels this
		// user is part of that their nick changed
		for _, v := range s.channelsOf(c) {
			v.ForAllMembersExcept(c, func(m *channel.Member) {
				m.WriteMessage(msg.New(nil, c.String(), "", "", "NICK", []string{nick}, false))
			})

			// update member map entry
			defer func(v *channel.Channel, oldNick string) {
				m, _ := v.GetMember(oldNick)
				v.DeleteMember(oldNick)
				v.SetMember(m)
			}(v, c.Nick)
		}

		if !changingCase {
			s.notify(c, prepMessage(RPL_MONOFFLINE, s.Name, "*", c.Id()), cap.None)
		}

		previousNuh := c.String()
		// update client map entry
		s.deleteClient(c.Nick)
		c.Nick = nick
		s.setClient(c)

		if !changingCase {
			s.notify(c, prepMessage(RPL_MONONLINE, s.Name, "*", c.Id()), cap.None)
		}

		return msg.New(nil, previousNuh, "", "", "NICK", []string{nick}, false)
	} else { // nick is being set for first time
		c.Nick = nick
		return s.endRegistration(c)
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

func USER(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if c.Is(client.Registered) {
		return prepMessage(ERR_ALREADYREGISTRED, s.Name, c.Id())
	} else if len(m.Params) < 4 || m.Params[3] == "" {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "USER")
	}

	modeBits, err := strconv.Atoi(m.Params[1])
	if err == nil {
		// only allow user to make themselves invis or wallops
		c.SetMode(client.Mode(modeBits) & (client.Invisible | client.Wallops))
	}

	c.User = m.Params[0]
	c.Realname = m.Params[3]
	return s.endRegistration(c)
}

func OPER(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 2 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "OPER")
	}

	name := m.Params[0]
	pass := m.Params[1]

	// will fail if username doesn't exist or if pass is incorrect
	if bcrypt.CompareHashAndPassword(s.Ops[name], []byte(pass)) != nil {
		return prepMessage(ERR_PASSWDMISMATCH, s.Name, c.Id())
	}

	c.SetMode(client.Op)

	return msg.Buffer{
		prepMessage(RPL_YOUREOPER, s.Name, c.Id()),
		msg.New(nil, s.Name, "", "", "MODE", []string{c.Nick, "+o"}, false),
	}
}

func QUIT(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	reason := c.Nick + " quit" // assume client does not send a reason for quit
	if len(m.Params) > 0 {
		reason = m.Params[0]
	}

	if !c.Is(client.Registered) {
		s.unknowns.Dec()
		s.ERROR(c, reason)
		return nil
	}

	s.whowasHistory.push(c.Nick, c.User, c.Host, c.Realname)
	s.notify(c, prepMessage(RPL_MONOFFLINE, s.Name, "*", c.Id()), cap.None)

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
	return nil
}

func (s *Server) endRegistration(c *client.Client) msg.Msg {
	if c.RegSuspended {
		return nil
	}
	if c.Nick == "" || c.User == "" { // tried to end without sending NICK & USER
		return nil
	}

	// client tried to finish registration with the nick of an already registered account
	if authn := s.userAccountForNickExists(c.Nick); authn != "" && c.SASLMech.Authn() != authn {
		return prepMessage(ERR_NICKNAMEINUSE, s.Name, c.Id(), c.Nick)
	}

	// we need this check here for the following situation: 1->NICK n;
	// 2->NICK n; 1-> USER u s e r; and then 2 tries to send USER, we
	// should reject 2's registration for having the same nick
	if _, ok := s.getClient(c.Nick); ok {
		return prepMessage(ERR_NICKNAMEINUSE, s.Name, c.Id(), c.Nick)
	}

	if s.Password != nil && !c.ServerPassAccepted {
		// write buffer to client first because QUIT will immediately close the underlying conn
		c.WriteMessage(prepMessage(ERR_PASSWDMISMATCH, s.Name, c.Id()))
		QUIT(s, c, &msg.Message{Params: []string{"Closing Link: " + s.Name + " (Bad Password)"}})
		return nil
	}

	c.SetMode(client.Registered)
	s.setClient(c)
	s.unknowns.Dec()
	s.max.KeepMax(uint64(s.clientLen()))

	buff := msg.Buffer{
		// send RPL_WELCOME and friends in acceptance
		prepMessage(RPL_WELCOME, s.Name, c.Id(), s.Network, c),
		prepMessage(RPL_YOURHOST, s.Name, c.Id(), s.Name),
		prepMessage(RPL_CREATED, s.Name, c.Id(), s.created),
		// serverName, version, userModes, chanModes
		prepMessage(RPL_MYINFO, s.Name, c.Id(), s.Name, "0", "ioOrw", "beliIkmstn"),
	}

	for _, support := range isupportTokens {
		buff.AddMsg(prepMessage(RPL_ISUPPORT, s.Name, c.Id(), support))
	}

	buff.AddMsg(LUSERS(s, c, nil))
	buff.AddMsg(MOTD(s, c, nil))

	// after registration burst, give clients max grants
	c.FillGrants()

	s.notify(c, prepMessage(RPL_MONONLINE, s.Name, "*", c), cap.None)
	return buff
}

func SETNAME(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 1 {
		s.stdReply(c, FAIL, "SETNAME", "INVALID_REALNAME", "", "Realname cannot be empty")
		return nil
	}

	c.Realname = m.Params[0]

	// "If a client sends a SETNAME command without having negotiated the
	// capability, the server SHOULD handle it silently (with no
	// response), as historic implementations did."
	if _, verbose := c.Caps[cap.Setname.Name]; !verbose {
		return nil
	}

	chans := s.channelsOf(c)
	for _, v := range chans {
		v.ForAllMembersExcept(c, func(m *channel.Member) {
			if !m.Caps[cap.Setname.Name] {
				return
			}
			m.WriteMessage(msg.New(nil, c.String(), "", "", "SETNAME", []string{c.Realname}, true))
		})
	}

	resp := msg.New(nil, c.String(), "", "", "SETNAME", []string{c.Realname}, true)
	s.notify(c, resp, cap.Setname)

	return resp
}

func JOIN(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 1 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "JOIN")
	}

	var buff msg.Buffer

	// when 'JOIN 0', PART from every channel client is a member of
	if m.Params[0] == "0" {
		for _, v := range s.channelsOf(c) {
			PART(s, c, &msg.Message{Params: []string{v.String()}})
		}
		return nil
	}

	chans := strings.Split(m.Params[0], ",")
	keys := make([]string, len(chans))
	if len(m.Params) >= 2 {
		// fill beginning of keys with the key m.Params
		k := strings.Split(m.Params[1], ",")
		copy(keys, k)
	}

	for i := range chans {
	chanExists:
		if ch, ok := s.getChannel(chans[i]); ok { // channel already exists
			err := ch.Admit(c, keys[i])
			if err != nil {
				if err == channel.ErrKeyMissing {
					buff.AddMsg(prepMessage(ERR_BADCHANNELKEY, s.Name, c.Id(), ch))
				} else if err == channel.ErrLimitReached { // not aceepting new clients
					buff.AddMsg(prepMessage(ERR_CHANNELISFULL, s.Name, c.Id(), ch))
				} else if err == channel.ErrNotInvited {
					buff.AddMsg(prepMessage(ERR_INVITEONLYCHAN, s.Name, c.Id(), ch))
				} else if err == channel.ErrBanned { // client is banned
					buff.AddMsg(prepMessage(ERR_BANNEDFROMCHAN, s.Name, c.Id(), ch))
				}
				return buff
			}

			// send JOIN to all participants of channel
			joinMsgParams := []string{ch.String(), c.SASLMech.Authn(), c.Realname}
			ch.ForAllMembersExcept(c, func(m *channel.Member) {
				if m.Caps[cap.ExtendedJoin.Name] {
					m.WriteMessage(msg.New(nil, c.Nick, c.User, c.Host, "JOIN", joinMsgParams, false))
				} else {
					m.WriteMessage(msg.New(nil, c.Nick, c.User, c.Host, "JOIN", joinMsgParams[:1], false))
				}
			})

			if c.Caps[cap.ExtendedJoin.Name] {
				buff.AddMsg(msg.New(nil, c.Nick, c.User, c.Host, "JOIN", joinMsgParams, false))
			} else {
				buff.AddMsg(msg.New(nil, c.Nick, c.User, c.Host, "JOIN", joinMsgParams[:1], false))
			}

			if ch.Topic != "" {
				// only send topic if it exists
				buff.AddMsg(TOPIC(s, c, &msg.Message{Params: []string{ch.String()}}))
			}
			buff.AddMsg(NAMES(s, c, &msg.Message{Params: []string{ch.String()}}))
			s.awayNotify(c, ch)
		} else { // create new channel
			s.joinLock.Lock()
			// two clients tried to create this channel at the same time, and
			// another client was able to finish channel creation before us.
			// have this client join the channel instead
			if _, chanAlreadyCreated := s.getChannel(chans[i]); chanAlreadyCreated {
				// retry this loop iteration
				s.joinLock.Unlock()
				goto chanExists
			}

			chanChar := channel.ChanType(chans[i][0])
			chanName := chans[i][1:]

			if !isValidChannelString(string(chanChar) + chanName) {
				buff.AddMsg(prepMessage(ERR_NOSUCHCHANNEL, s.Name, c.Id(), chans[i]))
				s.joinLock.Unlock()
				return buff
			}

			newChan := channel.New(chanName, chanChar)
			s.setChannel(newChan)
			newChan.SetMember(&channel.Member{Client: c, Prefix: channel.Operator})
			buff.AddMsg(msg.New(nil, c.String(), "", "", "JOIN", []string{newChan.String()}, false))

			buff.AddMsg(NAMES(s, c, &msg.Message{Params: []string{newChan.String()}}))
			s.joinLock.Unlock()
		}
	}
	return buff
}

func isValidChannelString(ch string) bool {
	if len(ch) == 0 {
		return false
	}

	_, isPrefix := channel.MemberPrefix[ch[0]]
	if !isPrefix && ch[0] != byte(channel.Remote) && ch[0] != byte(channel.Local) {
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

func PART(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	chans := strings.Split(m.Params[0], ",")

	params := make([]string, 1)
	if len(m.Params) > 1 {
		params = append(params, m.Params[1])
	}

	for _, v := range chans {
		ch, errMsg := s.clientBelongstoChan(c, v)
		if ch == nil {
			return errMsg
		}

		params[0] = ch.String()
		ch.WriteMessage(msg.New(nil, c.String(), "", "", "PART", params, len(params) > 1))

		if ch.Len() == 1 {
			s.deleteChannel(ch.String())
		} else {
			ch.DeleteMember(c.Nick)
		}
	}

	return nil
}

func TOPIC(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 1 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "TOPIC")
	}

	ch, errMsg := s.clientBelongstoChan(c, m.Params[0])
	if ch == nil {
		return errMsg
	}

	if len(m.Params) >= 2 { // modify topic
		if m, _ := ch.GetMember(c.Nick); ch.Protected && !m.Is(channel.Operator) {
			return prepMessage(ERR_CHANOPRIVSNEEDED, s.Name, c.Id(), ch)
		}
		ch.Topic = m.Params[1]
		ch.TopicSetBy = c
		ch.TopicSetAt = time.Now()
		ch.WriteMessage(msg.New(nil, s.Name, "", "", "TOPIC", []string{ch.String(), ch.Topic}, true))
		return nil
	} else {
		if ch.Topic == "" {
			return prepMessage(RPL_NOTOPIC, s.Name, c.Id(), ch)
		} else { // give back existing topic
			return msg.Buffer{
				prepMessage(RPL_TOPIC, s.Name, c.Id(), ch, ch.Topic),
				prepMessage(RPL_TOPICWHOTIME, s.Name, c.Id(), ch, ch.TopicSetBy, ch.TopicSetAt.Unix()),
			}
		}
	}
}

func INVITE(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 2 {
		chans := s.getChannelsClientInvitedTo(c)
		var buff msg.Buffer
		for _, v := range chans {
			buff.AddMsg(prepMessage(RPL_INVITELIST, s.Name, c.Id(), v))
		}
		buff.AddMsg(prepMessage(RPL_ENDOFINVITELIST, s.Name, c.Id()))
		return buff
	}

	nick := m.Params[0]
	ch, ok := s.getChannel(m.Params[1])
	if !ok { // channel does not exist
		return prepMessage(ERR_NOSUCHCHANNEL, s.Name, c.Id(), m.Params[1])
	}

	sender, _ := ch.GetMember(c.Nick)
	recipient, _ := s.getClient(nick)
	if sender == nil { // only members can invite
		return prepMessage(ERR_NOTONCHANNEL, s.Name, c.Id(), ch)
	} else if ch.Invite && !sender.Is(channel.Operator) { // if invite mode set, only ops can send an invite
		return prepMessage(ERR_CHANOPRIVSNEEDED, s.Name, c.Id(), ch)
	} else if recipient == nil { // nick not on server
		return prepMessage(ERR_NOSUCHNICK, s.Name, c.Id(), nick)
	} else if _, ok := ch.GetMember(nick); ok { // can't invite a member who is already on channel
		return prepMessage(ERR_USERONCHANNEL, s.Name, c.Id(), nick, ch)
	}

	ch.Invited = append(ch.Invited, nick)

	recipient.WriteMessageFrom(msg.New(nil, sender.Nick, sender.User, sender.Host, "INVITE", []string{nick, ch.String()}, false), c)
	ch.ForAllMembers(func(m *channel.Member) {
		if m.Caps[cap.InviteNotify.Name] {
			m.WriteMessageFrom(msg.New(nil, sender.Nick, sender.User, sender.Host, "INVITE", []string{nick, ch.String()}, false), c)
		}
	})

	return prepMessage(RPL_INVITING, s.Name, c.Id(), nick, ch)
}

// if c belongs to the channel associated with chanName, return that
// channel. If it doesn't, or if the channel doesn't exist, write a
// numeric reply to the client and return nil.
func (s *Server) clientBelongstoChan(c *client.Client, chanName string) (*channel.Channel, msg.Msg) {
	ch, ok := s.getChannel(chanName)
	if !ok { // channel not found
		return nil, prepMessage(ERR_NOSUCHCHANNEL, s.Name, c.Id(), chanName)
	} else {
		if _, ok := ch.GetMember(c.Nick); !ok { // client does not belong to channel
			return nil, prepMessage(ERR_NOTONCHANNEL, s.Name, c.Id(), ch)
		}
	}
	return ch, nil
}

// either one chan with many nicks, or 1 chan per nick
func KICK(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 2 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "KICK")
	}

	comment := c.Nick
	if len(m.Params) == 3 {
		comment = m.Params[2]
	}

	chans := strings.Split(m.Params[0], ",")
	users := strings.Split(m.Params[1], ",")
	if !(len(chans) == 1 && len(users) > 0) && !(len(chans) == len(users)) {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "KICK")
	}

	// fill chans with copies of itself
	if len(chans) == 1 {
		singleChan := chans[0]
		chans = make([]string, len(users))
		for i := range chans {
			chans[i] = singleChan
		}
	}

	var buff msg.Buffer
	// len(chans)==len(users) here
	for i := 0; i < len(chans); i++ {
		ch, _ := s.getChannel(chans[i])
		if ch == nil {
			return prepMessage(ERR_NOSUCHCHANNEL, s.Name, c.Id(), chans[i])
		}
		self, _ := ch.GetMember(c.Nick)
		if self == nil {
			return prepMessage(ERR_NOTONCHANNEL, s.Name, c.Id(), ch)
		} else if !self.Is(channel.Operator) {
			return prepMessage(ERR_CHANOPRIVSNEEDED, s.Name, c.Id(), ch)
		}

		if errMsg := s.kickMember(c, ch, users[i], comment); errMsg != nil {
			buff.AddMsg(errMsg)
		}
	}
	return buff
}

// Given a nickname, determine if they belong to the Channel ch and kick
// them. If a comment is given, it will be sent along with the KICK.
func (s *Server) kickMember(c *client.Client, ch *channel.Channel, memberNick string, comment string) msg.Msg {
	u, _ := ch.GetMember(memberNick)
	if u == nil {
		return prepMessage(ERR_USERNOTINCHANNEL, s.Name, c.Id(), memberNick, ch)
	}

	// send KICK to all channel members but self
	ch.ForAllMembersExcept(c, func(m *channel.Member) {
		m.WriteMessageFrom(msg.New(nil, c.Nick, c.User, c.Host, "KICK", []string{ch.String(), u.Nick, comment}, true), c)
	})

	ch.DeleteMember(u.Nick)
	return nil
}

func NAMES(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) == 0 {
		return prepMessage(RPL_ENDOFNAMES, s.Name, c.Id(), "*")
	}

	var buff msg.Buffer
	chans := strings.Split(m.Params[0], ",")
	for _, v := range chans {
		ch, _ := s.getChannel(v)
		if ch == nil {
			continue
		} else {
			_, ok := ch.GetMember(c.Nick)
			if ch.Secret && !ok { // chan is secret and client does not belong
				continue
			} else {
				sym, members := constructNAMREPLY(ch, ok, c.Caps[cap.MultiPrefix.Name], c.Caps[cap.UserhostInNames.Name])
				buff.AddMsg(prepMessage(RPL_NAMREPLY, s.Name, c.Id(), sym, ch, members))
			}
		}
	}
	buff.AddMsg(prepMessage(RPL_ENDOFNAMES, s.Name, c.Id(), m.Params[0]))
	return buff
}

func LIST(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	buff := &msg.Buffer{}
	defer buff.AddMsg(prepMessage(RPL_LISTEND, s.Name, c.Id()))

	if len(m.Params) == 0 {
		// reply with all channels that aren't secret
		for _, v := range s.channels.all() {
			if listReply := s.sendListReply(v, c); listReply != nil {
				buff.AddMsg(listReply)
			}
		}
		return buff
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
		for _, v := range s.channels.all() {
			chans[i] = v.String()
			i++
		}
	}

	replies := []*channel.Channel{}
	for _, v := range chans {
		if ch, ok := s.getChannel(v); ok {
			replies = append(replies, ch)
		}
	}

	for _, v := range elist {
		if len(v) == 0 {
			continue
		}
		replies = s.applyElistConditions(v, replies)
	}

	for _, v := range replies {
		if listReply := s.sendListReply(v, c); listReply != nil {
			buff.AddMsg(listReply)
		}
	}

	return buff
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
		if len(pattern) < 2 {
			break
		}

		lessThan := pattern[1] == '<'
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
		if len(pattern) < 2 {
			break
		}

		lessThan := pattern[1] == '<'
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

func (s *Server) sendListReply(ch *channel.Channel, c *client.Client) msg.Msg {
	_, ok := ch.GetMember(c.Nick)
	// skip sending reply for secret channel unless this client is a
	// member of that channel
	if ch.Secret && !ok {
		return nil
	}
	return prepMessage(RPL_LIST, s.Name, c.Id(), ch, ch.Len(), ch.Topic)
}

func MOTD(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(s.motd) == 0 {
		return prepMessage(ERR_NOMOTD, s.Name, c.Id())
	}

	var buff msg.Buffer

	buff.AddMsg(prepMessage(RPL_MOTDSTART, s.Name, c.Id(), s.Name))
	for _, v := range s.motd {
		buff.AddMsg(prepMessage(RPL_MOTD, s.Name, c.Id(), v))
	}
	buff.AddMsg(prepMessage(RPL_ENDOFMOTD, s.Name, c.Id()))
	return buff
}

func LUSERS(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	invis := 0
	ops := 0
	clientSize := s.clientLen()
	max := s.max.Get()

	for _, v := range s.clients.all() {
		if v.Is(client.Invisible) {
			invis++
			continue
		}
		if v.Is(client.Op) {
			ops++
		}
	}

	return msg.Buffer{
		prepMessage(RPL_LUSERCLIENT, s.Name, c.Id(), clientSize, invis, 1),
		prepMessage(RPL_LUSEROP, s.Name, c.Id(), ops),
		prepMessage(RPL_LUSERUNKNOWN, s.Name, c.Id(), s.unknowns.Get()),
		prepMessage(RPL_LUSERCHANNELS, s.Name, c.Id(), s.channelLen()),
		prepMessage(RPL_LUSERME, s.Name, c.Id(), clientSize, 1),
		prepMessage(RPL_LOCALUSERS, s.Name, c.Id(), clientSize, max, clientSize, max),
		prepMessage(RPL_GLOBALUSERS, s.Name, c.Id(), clientSize, max, clientSize, max),
	}
}

func TIME(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	return prepMessage(RPL_TIME, s.Name, c.Id(), s.Name, time.Now().Local())
}

// TODO: support commands like this that intersperse the modechar and modem.Params MODE &oulu +b *!*@*.edu +e *!*@*.bu.edu
func MODE(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 1 { // give back own mode
		return prepMessage(RPL_UMODEIS, s.Name, c.Id(), c.Mode)
	}

	target := m.Params[0]
	if !isValidChannelString(target) {
		client, ok := s.getClient(target)
		if !ok {
			return prepMessage(ERR_NOSUCHNICK, s.Name, c.Id(), target)
		}
		if client.Nick != c.Nick { // can't modify another user
			return prepMessage(ERR_USERSDONTMATCH, s.Name, c.Id())
		}

		if len(m.Params) == 2 { // modify own mode
			var buff msg.Buffer
			appliedModes := []mode.Mode{}
			for _, v := range mode.Parse([]byte(m.Params[1])) {
				found := c.ApplyMode(v)
				if !found {
					buff.AddMsg(prepMessage(ERR_UMODEUNKNOWNFLAG, s.Name, c.Id()))
				} else {
					appliedModes = append(appliedModes, v)
				}
			}

			modeStr := buildModestr(appliedModes)
			buff.AddMsg(msg.New(nil, s.Name, "", "", "MODE", []string{c.Nick, modeStr}, false))
			return buff
		} else { // give back own mode
			return prepMessage(RPL_UMODEIS, s.Name, c.Id(), c.Mode)
		}
	} else {
		ch, ok := s.getChannel(target)
		if !ok {
			return prepMessage(ERR_NOSUCHCHANNEL, s.Name, c.Id(), target)
		}

		if len(m.Params) == 1 { // modeStr not given, give back channel modes
			modeStr, params := ch.Modes()
			if len(params) != 0 {
				modeStr += " "
			}

			return msg.Buffer{
				prepMessage(RPL_CHANNELMODEIS, s.Name, c.Id(), ch, modeStr, strings.Join(params, " ")),
				prepMessage(RPL_CREATIONTIME, s.Name, c.Id(), ch, ch.CreatedAt),
			}
		} else { // modeStr given
			if self, belongs := ch.GetMember(c.Id()); !belongs || !self.Is(channel.Operator) {
				return prepMessage(ERR_CHANOPRIVSNEEDED, s.Name, c.Id(), ch)
			}

			var buff msg.Buffer
			modes := mode.Parse([]byte(m.Params[1]))
			channel.PrepareModes(modes, m.Params[2:])
			appliedModes := []mode.Mode{}
			for _, m := range modes {
				if m.Type == mode.List {
					switch m.ModeChar {
					case 'b':
						buff.AddMsg(s.sendChannelModeList(c, ch, ch.Ban, RPL_BANLIST, RPL_ENDOFBANLIST))
					case 'e':
						buff.AddMsg(s.sendChannelModeList(c, ch, ch.BanExcept, RPL_EXCEPTLIST, RPL_ENDOFEXCEPTLIST))
					case 'I':
						buff.AddMsg(s.sendChannelModeList(c, ch, ch.InviteExcept, RPL_INVEXLIST, RPL_ENFOFINVEXLIST))
					}
					continue
				}
				err := ch.ApplyMode(m)
				if errors.Is(err, channel.ErrNeedMoreParams) {
					return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), err)
				} else if errors.Is(err, channel.ErrUnknownMode) {
					return prepMessage(ERR_UNKNOWNMODE, s.Name, c.Id(), err, ch)
				} else if errors.Is(err, channel.ErrNotInChan) {
					// if client wasnt in the channel, do a final check to see if they're even on the server
					if _, exists := s.getClient(m.Param); m.Param != "" && !exists {
						return prepMessage(ERR_NOSUCHNICK, s.Name, c.Id(), m.Param)
					}

					return prepMessage(ERR_USERNOTINCHANNEL, s.Name, c.Id(), err, ch)
				} else if errors.Is(err, channel.ErrInvalidKey) {
					return prepMessage(ERR_INVALIDKEY, s.Name, c.Id(), ch)
				} else {
					appliedModes = append(appliedModes, m)
				}
			}

			modeStr := buildModestr(appliedModes)

			// only write final MODE to channel if any mode was actually altered
			if modeStr != "" {
				ch.WriteMessageFrom(msg.New(nil, s.Name, "", "", "MODE", []string{ch.String(), modeStr}, false), c)
			}
			return buff
		}
	}
}

func buildModestr(modes []mode.Mode) string {
	applied := []byte{}
	removed := []byte{}
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
func (s *Server) sendChannelModeList(c *client.Client, ch *channel.Channel, list []string, dataResponse *msg.Message, endResponse *msg.Message) msg.Msg {
	var buff msg.Buffer
	for _, v := range list {
		buff.AddMsg(prepMessage(dataResponse, s.Name, c.Id(), ch, v))
	}
	buff.AddMsg(prepMessage(endResponse, s.Name, c.Id(), ch))
	return buff
}

func INFO(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	return msg.Buffer{
		prepMessage(RPL_INFO, s.Name, c.Id(), "gossip is licensed under GPLv3"),
		prepMessage(RPL_ENDOFINFO, s.Name, c.Id()),
	}
}

func WHO(s *Server, c *client.Client, m *msg.Message) msg.Msg {
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

	var buff msg.Buffer

	// first, try to match channels exactly against the mask. if exists,
	// returns WHOREPLY for every member in channel. else, we will match
	// exactly against the client name.
	if ch, ok := s.getChannel(mask); ok {
		ch.ForAllMembers(func(m *channel.Member) {
			if whox {
				resp := constructSpcrplResponse(fields, m.Client, s)
				buff.AddMsg(prepMessage(RPL_WHOSPCRPL, s.Name, c.Id(), resp))
			} else {
				flags := whoreplyFlagsForMember(m, c.Caps[cap.MultiPrefix.Name])
				buff.AddMsg(prepMessage(RPL_WHOREPLY, s.Name, c.Id(), ch, m.User, m.Host, s.Name, m.Nick, flags, m.Realname))
			}
		})
		buff.AddMsg(prepMessage(RPL_ENDOFWHO, s.Name, c.Id(), mask))
		return buff
	}

	// no channel results found, match against a single client
	whoClient, ok := s.getClient(mask)
	if ok {
		if whox {
			resp := constructSpcrplResponse(fields, whoClient, s)
			buff.AddMsg(prepMessage(RPL_WHOSPCRPL, s.Name, c.Id(), resp))
		} else {
			flags := whoreplyFlagsForClient(whoClient)
			buff.AddMsg(prepMessage(RPL_WHOREPLY, s.Name, c.Id(), "*", whoClient.User, whoClient.Host, s.Name, whoClient.Nick, flags, whoClient.Realname))
		}
		buff.AddMsg(prepMessage(RPL_ENDOFWHO, s.Name, c.Id(), mask))
		return buff
	}

	// no exact client matches, so use mask to match against all visible clients
	onlyOps := len(m.Params) > 1 && m.Params[1] == "o"
	for _, v := range s.clients.all() {
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
				buff.AddMsg(prepMessage(RPL_WHOSPCRPL, s.Name, c.Id(), resp))
			} else {
				flags := whoreplyFlagsForClient(v)
				buff.AddMsg(prepMessage(RPL_WHOREPLY, s.Name, c.Id(), "*", v.User, v.Host, s.Name, v.Nick, flags, v.Realname))
			}
		}
	}
	buff.AddMsg(prepMessage(RPL_ENDOFWHO, s.Name, c.Id(), mask))
	return buff
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
			resp[i] = strconv.Itoa(int(time.Since(c.IdleTime()).Seconds()))
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
func WHOIS(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	// silently ignore empty m.Params
	if len(m.Params) < 1 {
		return nil
	}

	// ignore optional target param
	nicks := m.Params[0]
	if len(m.Params) == 2 {
		nicks = m.Params[1]
	}

	var buff msg.Buffer

	masks := strings.Split(strings.ToLower(nicks), ",")
	for _, m := range masks {
		if v, ok := s.getClient(m); ok {
			buff.AddMsg(s.sendWHOIS(c, v))
			continue
		}

		// this is a mask param
		if strings.ContainsAny(m, "*?") {
			for _, v := range s.clients.all() {
				if wild.Match(m, v.Nick) {
					buff.AddMsg(s.sendWHOIS(c, v))
				}
			}
		} else { // was not a mask AND did not find a nick that matched
			buff.AddMsg(prepMessage(ERR_NOSUCHNICK, s.Name, c.Id(), m))
		}
	}

	buff.AddMsg(prepMessage(RPL_ENDOFWHOIS, s.Name, c.Id(), m.Params[0]))
	return buff
}

func (s *Server) sendWHOIS(c *client.Client, v *client.Client) msg.Buffer {
	var buff msg.Buffer

	if v.Is(client.Away) {
		buff.AddMsg(prepMessage(RPL_AWAY, s.Name, c.Id(), v.Nick, v.AwayMsg))
	}

	buff.AddMsg(prepMessage(RPL_WHOISUSER, s.Name, c.Id(), v.Nick, v.User, v.Host, v.Realname))
	buff.AddMsg(prepMessage(RPL_WHOISSERVER, s.Name, c.Id(), v.Nick, s.Name, "wip irc server"))
	if v.Is(client.Bot) {
		buff.AddMsg(prepMessage(RPL_WHOISBOT, s.Name, c.Id(), v.Nick))
	}
	if v.Is(client.Op) {
		buff.AddMsg(prepMessage(RPL_WHOISOPERATOR, s.Name, c.Id(), v.Nick))
	}
	if v == c || c.Is(client.Op) { // querying whois on self or self is an op
		certPrint, err := v.CertificateFingerprint()
		if err == nil {
			buff.AddMsg(prepMessage(RPL_WHOISCERTFP, s.Name, c.Id(), v.Nick, certPrint))
		}
	}
	buff.AddMsg(prepMessage(RPL_WHOISIDLE, s.Name, c.Id(), v.Nick, time.Since(v.IdleTime()).Round(time.Second).Seconds(), v.JoinTime))

	chans := []string{}
	for _, k := range s.channels.all() {
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

	chanParam := ""
	if len(chans) > 0 {
		chanParam = " :" + strings.Join(chans, " ")
	}
	buff.AddMsg(prepMessage(RPL_WHOISCHANNELS, s.Name, c.Id(), v.Nick, chanParam))

	if v.IsAuthenticated {
		buff.AddMsg(prepMessage(RPL_WHOISACCOUNT, s.Name, c.Id(), v.Nick, v.SASLMech.Authn()))
	}

	if v.IsSecure() {
		buff.AddMsg(prepMessage(RPL_WHOISSECURE, s.Name, c.Id(), v.Nick))
	}
	return buff
}

func WHOWAS(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 1 {
		return prepMessage(ERR_NONICKNAMEGIVEN, s.Name, c.Id())
	}

	count := s.whowasHistory.len()
	if len(m.Params) > 1 {
		givenCount, _ := strconv.Atoi(m.Params[1])
		// negative counts should be treated as wanting to traverse the entire history
		if givenCount > 0 {
			count = givenCount
		}
	}

	var buff msg.Buffer

	nicks := strings.Split(m.Params[0], ",")
	info := s.whowasHistory.search(nicks, count)
	if len(info) == 0 {
		buff.AddMsg(prepMessage(ERR_WASNOSUCHNICK, s.Name, c.Id(), m.Params[0]))
		buff.AddMsg(prepMessage(RPL_ENDOFWHOWAS, s.Name, c.Id(), m.Params[0]))
		return buff
	}

	for _, v := range info {
		buff.AddMsg(prepMessage(RPL_WHOWASUSER, s.Name, c.Id(), v.nick, v.user, v.host, v.realname))
	}
	buff.AddMsg(prepMessage(RPL_ENDOFWHOWAS, s.Name, c.Id(), m.Params[0]))
	return buff
}

func PRIVMSG(s *Server, c *client.Client, m *msg.Message) msg.Msg { return s.communicate(m, c) }
func NOTICE(s *Server, c *client.Client, m *msg.Message) msg.Msg  { return s.communicate(m, c) }

// communicate is used for PRIVMSG/NOTICE
func (s *Server) communicate(m *msg.Message, c *client.Client) msg.Msg {
	msgCopy := *m
	// "Tags without the client-only prefix MUST be removed by the
	// server before being relayed with any message to another client."
	msgCopy.TrimNonClientTags()
	msgCopy.Nick = c.Nick
	msgCopy.Host = c.Host
	msgCopy.User = c.User

	skipReplies := m.Command == "NOTICE" || m.Command == "TAGMSG"

	if (len(m.Params) < 2 || m.Params[1] == "") && m.Command != "TAGMSG" {
		if !skipReplies {
			return prepMessage(ERR_NOTEXTTOSEND, s.Name, c.Id())
		}
		return nil
	}

	var buff msg.Buffer
	recipients := strings.Split(m.Params[0], ",")
	for _, v := range recipients {
		msgCopy.Params[0] = v

		if isValidChannelString(v) {
			chanName := v
			prefix, hasPrefix := channel.MemberPrefix[chanName[0]]
			if hasPrefix {
				chanName = chanName[1:]
			}

			ch, _ := s.getChannel(chanName)
			if ch == nil { // channel doesn't exist
				if !skipReplies {
					buff.AddMsg(prepMessage(ERR_NOSUCHCHANNEL, s.Name, c.Id(), chanName))
				}
				continue
			}

			self, _ := ch.GetMember(c.Nick)
			if self == nil {
				if ch.NoExternal {
					// chan does not allow external messages; client needs to join
					if !skipReplies {
						buff.AddMsg(prepMessage(ERR_CANNOTSENDTOCHAN, s.Name, c.Id(), ch))
					}
					continue
				}
			} else if ch.Moderated && self.Prefix == 0 {
				// member has no mode, so they cannot speak in a moderated chan
				if !skipReplies {
					buff.AddMsg(prepMessage(ERR_CANNOTSENDTOCHAN, s.Name, c.Id(), ch))
				}
				continue
			}

			// write to everybody else in the chan besides self
			ch.ForAllMembersExcept(c, func(m *channel.Member) {
				if hasPrefix && !m.Is(prefix) {
					return
				}

				if msgCopy.Command == "TAGMSG" && !m.Caps[cap.MessageTags.Name] {
					return
				}
				if m.Caps[cap.MessageTags.Name] {
					msgCopy.SetMsgid()
				}
				m.WriteMessageFrom(&msgCopy, c)
			})
		} else { // client->client
			target, ok := s.getClient(v)
			if !ok {
				if !skipReplies {
					buff.AddMsg(prepMessage(ERR_NOSUCHNICK, s.Name, c.Id(), v))
				}
				continue
			}

			if target.Is(client.Away) {
				buff.AddMsg(prepMessage(RPL_AWAY, s.Name, c.Id(), target.Nick, target.AwayMsg))
				continue
			}
			if msgCopy.Command == "TAGMSG" && !target.Caps[cap.MessageTags.Name] {
				continue
			}
			if target.Caps[cap.MessageTags.Name] {
				msgCopy.SetMsgid()
			}
			target.WriteMessageFrom(&msgCopy, c)
		}

		if c.Caps[cap.EchoMessage.Name] {
			if !c.HasMessageTags() {
				buff.AddMsg(msgCopy.RemoveAllTags())
			} else {
				buff.AddMsg(&msgCopy)
			}
		}
	}

	return buff
}

func PING(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 1 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "PING")
	}
	return msg.New(nil, s.Name, "", "", "PONG", []string{s.Name, m.Params[0]}, m.Params[0] == "")
}

func PONG(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	c.PONG <- struct{}{}
	return nil
}

// this is currently a noop, as a server should only accept ERROR
// commands from other servers
func ERROR(s *Server, c *client.Client, m *msg.Message) msg.Msg { return nil }

func AWAY(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	defer s.awayNotify(c, s.channelsOf(c)...)

	// remove away
	if len(m.Params) == 0 || m.Params[0] == "" {
		c.AwayMsg = ""
		c.UnsetMode(client.Away)
		return prepMessage(RPL_UNAWAY, s.Name, c.Id())
	}

	c.AwayMsg = m.Params[0]
	c.SetMode(client.Away)
	return prepMessage(RPL_NOWAWAY, s.Name, c.Id())
}

func (s *Server) awayNotify(c *client.Client, chans ...*channel.Channel) {
	for _, v := range chans {
		v.ForAllMembersExcept(c, func(m *channel.Member) {
			if m.Caps[cap.AwayNotify.Name] {
				m.WriteMessage(msg.New(nil, c.String(), "", "", "AWAY", []string{c.AwayMsg}, strings.Contains(c.AwayMsg, " ")))
			}
		})
	}
	s.notify(c, msg.New(nil, c.String(), "", "", "AWAY", []string{c.AwayMsg}, strings.Contains(c.AwayMsg, " ")), cap.AwayNotify)
}

func REHASH(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if !c.Is(client.Op) {
		return prepMessage(ERR_NOPRIVILEGES, s.Name, c.Id())
	}

	conf, _ := NewConfig(s.configSource)
	s.Config = conf

	fileName := s.configSource.(*os.File).Name()
	return prepMessage(RPL_REHASHING, s.Name, c.Id(), fileName)
}

func USERHOST(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 1 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "USERHOST")
	}

	replies := make([]string, 0, len(m.Params))
	for _, nick := range m.Params {
		client, ok := s.getClient(nick)
		if ok {
			replies = append(replies, constructUserhostReply(client))
		}
	}
	return prepMessage(RPL_USERHOST, s.Name, c.Id(), strings.Join(replies, " "))
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

func WALLOPS(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 1 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "WALLOPS")
	}

	if !c.Is(client.Op) {
		return prepMessage(ERR_NOPRIVILEGES, s.Name, c.Id())
	}

	m.Nick = c.Nick
	m.User = c.User
	m.Host = c.Host

	for _, v := range s.clients.all() {
		if v.Is(client.Wallops) {
			v.WriteMessage(m)
		}
	}
	return nil
}

func (s *Server) executeMessage(m *msg.Message, c *client.Client) {
	upper := strings.ToUpper(m.Command)
	// ignore unregistered user commands until registration completes
	if !c.Is(client.Registered) && (upper != "CAP" && upper != "NICK" && upper != "USER" && upper != "PASS" && upper != "AUTHENTICATE" && upper != "QUIT" && upper != "PING") {
		s.writeReply(c, ERR_NOTREGISTERED)
		return
	}

	hasLabel, label := m.HasTag("label")

	if e, ok := commands[upper]; ok {
		resp := e(s, c, m)

		// check if we need to batch these messages
		if c.Caps[cap.LabeledResponses.Name] {
			// send ACK
			if hasLabel && resp == nil {
				c.WriteMessage(msg.New([]msg.Tag{{Key: "label", Value: label}}, s.Name, "", "", "ACK", nil, false))
				return
			}

			if r, ok := resp.(msg.Buffer); ok && hasLabel {
				resp = r.WrapInBatch(msg.Label)
			}
			if hasLabel {
				resp.AddTag("label", label)
			}
		}

		if resp != nil {
			c.WriteMessage(resp)
		}
		c.UpdateIdleTime(time.Now())
	} else {
		errMsg := prepMessage(ERR_UNKNOWNCOMMAND, s.Name, c.Id(), m.Command)
		if c.Caps[cap.LabeledResponses.Name] && hasLabel {
			errMsg.AddTag("label", label)
		}
		c.WriteMessage(errMsg)
	}
}
