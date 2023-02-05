package server

import (
	"fmt"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

const (
	RPL_WELCOME          = ":%s 001 %s :Welcome to the %s IRC Network %s\r\n"
	RPL_YOURHOST         = ":%s 002 %s :Your host is %s\r\n"
	RPL_CREATED          = ":%s 003 %s :This server was created %s\r\n"
	RPL_MYINFO           = ":%s 004 %s %s %s %s %s\r\n"
	RPL_ISUPPORT         = ":%s 005 %s %s :are supported by this server\r\n"
	RPL_UMODEIS          = ":%s 221 %s %s\r\n"
	RPL_LUSERCLIENT      = ":%s 251 %s :There are %d users and %d invisible on %d servers\r\n"
	RPL_LUSEROP          = ":%s 252 %s %d :operator(s) online\r\n"
	RPL_LUSERUNKNOWN     = ":%s 253 %s %d :unknown connection(s)\r\n"
	RPL_LUSERCHANNELS    = ":%s 254 %s %d :channels formed\r\n"
	RPL_LUSERME          = ":%s 255 %s :I have %d clients and %d servers\r\n"
	RPL_LOCALUSERS       = ":%s 265 %s %v %v :Current local users %v, max %v\r\n"
	RPL_GLOBALUSERS      = ":%s 266 %s %v %v :Current global users %v, max %v\r\n"
	RPL_WHOISCERTFP      = ":%s 276 %s %s :has client certificate fingerprint %s\r\n"
	RPL_AWAY             = ":%s 301 %s %s :%s\r\n"
	RPL_USERHOST         = ":%s 302 %s :%s\r\n"
	RPL_UNAWAY           = ":%s 305 %s :You are no longer marked as being away\r\n"
	RPL_NOWAWAY          = ":%s 306 %s :You have been marked as being away\r\n"
	RPL_WHOISUSER        = ":%s 311 %s %s %s %s * :%s\r\n"
	RPL_WHOISSERVER      = ":%s 312 %s %s %s :%s\r\n"
	RPL_WHOISOPERATOR    = ":%s 313 %s %s :is an IRC operator\r\n"
	RPL_WHOWASUSER       = ":%s 314 %s %s %s %s * %s\r\n"
	RPL_WHOISIDLE        = ":%s 317 %s %s %v %v :seconds idle, signon time\r\n"
	RPL_ENDOFWHOIS       = ":%s 318 %s %s :End of /WHOIS list\r\n"
	RPL_WHOISCHANNELS    = ":%s 319 %s %s%s\r\n"
	RPL_ENDOFWHO         = ":%s 315 %s %s :End of WHO list\r\n"
	RPL_LIST             = ":%s 322 %s %s %v :%s\r\n"
	RPL_LISTEND          = ":%s 323 %s :End of /LIST\r\n"
	RPL_CHANNELMODEIS    = ":%s 324 %s %s %s%s\r\n"
	RPL_CREATIONTIME     = ":%s 329 %s %s %s\r\n"
	RPL_WHOISACCOUNT     = ":%s 330 %s %s %s :is logged in as\r\n"
	RPL_NOTOPIC          = ":%s 331 %s %s :No topic is set\r\n"
	RPL_TOPIC            = ":%s 332 %s %s :%s\r\n"
	RPL_TOPICWHOTIME     = ":%s 333 %s %s %s %v\r\n"
	RPL_WHOISBOT         = ":%s 335 %s %s :bot\r\n"
	RPL_INVITING         = ":%s 341 %s %s %s\r\n"
	RPL_INVITELIST       = ":%s 346 %s %s %s\r\n"
	RPL_ENDOFINVITELIST  = ":%s 347 %s %s :End of channel invite list\r\n"
	RPL_EXCEPTLIST       = ":%s 348 %s %s %s\r\n"
	RPL_ENDOFEXCEPTLIST  = ":%s 349 %s %s :End of channel exception list\r\n"
	RPL_WHOREPLY         = ":%s 352 %s %s %s %s %s %s %s :0 %s\r\n"
	RPL_NAMREPLY         = ":%s 353 %s %s %s :%s\r\n"
	RPL_WHOSPCRPL        = ":%s 354 %s %s\r\n"
	RPL_ENDOFNAMES       = ":%s 366 %s %s :End of /NAMES list\r\n"
	RPL_BANLIST          = ":%s 367 %s %s %s\r\n"
	RPL_ENDOFBANLIST     = ":%s 368 %s %s :End of channel ban list\r\n"
	RPL_ENDOFWHOWAS      = ":%s 369 %s %s :End of WHOWAS\r\n"
	RPL_MOTDSTART        = ":%s 375 %s :- %s Message of the Day -\r\n"
	RPL_INFO             = ":%s 371 %s :%s\r\n"
	RPL_MOTD             = ":%s 372 %s :%s\r\n"
	RPL_ENDOFINFO        = ":%s 374 %s :End of INFO list\r\n"
	RPL_ENDOFMOTD        = ":%s 376 %s :End of /MOTD command\r\n"
	RPL_YOUREOPER        = ":%s 381 %s :You are now an IRC operator\r\n"
	RPL_REHASHING        = ":%s 382 %s %s :Rehashing\r\n"
	RPL_TIME             = ":%s 391 %s %s :%s\r\n"
	ERR_NOSUCHNICK       = ":%s 401 %s %s :No such nick/channel\r\n"
	ERR_NOSUCHCHANNEL    = ":%s 403 %s %s :No such channel\r\n"
	ERR_CANNOTSENDTOCHAN = ":%s 404 %s %s :Cannot send to channel\r\n"
	ERR_WASNOSUCHNICK    = ":%s 406 %s %s :There was no such nickname\r\n"
	ERR_INVALIDCAPCMD    = ":%s 410 %s %s :Invalid CAP command\r\n"
	ERR_NORECIPIENT      = ":%s 411 %s :No recipient given (%s)\r\n"
	ERR_NOTEXTTOSEND     = ":%s 412 %s :No text to send\r\n"
	ERR_INPUTTOOLONG     = ":%s 417 %s :Input line was too long\r\n"
	ERR_UNKNOWNCOMMAND   = ":%s 421 %s %s :Unknown command\r\n"
	ERR_NOMOTD           = ":%s 422 %s :MOTD file is missing\r\n"
	ERR_NONICKNAMEGIVEN  = ":%s 431 %s :No nickname given\r\n"
	ERR_ERRONEUSNICKNAME = ":%s 432 %s :Erroneous nickname\r\n"
	ERR_NICKNAMEINUSE    = ":%s 433 %s %s :Nickname is already in use\r\n"
	ERR_USERNOTINCHANNEL = ":%s 441 %s %s %s :They aren't on that channel\r\n"
	ERR_NOTONCHANNEL     = ":%s 442 %s %s :You're not on that channel\r\n"
	ERR_USERONCHANNEL    = ":%s 443 %s %s %s :is already on channel\r\n"
	ERR_NOTREGISTERED    = ":%s 451 %s :You have not registered\r\n"
	ERR_NEEDMOREPARAMS   = ":%s 461 %s %s :Not enough parameters\r\n"
	ERR_ALREADYREGISTRED = ":%s 462 %s :You may not reregister\r\n"
	ERR_PASSWDMISMATCH   = ":%s 464 %s :Password Incorrect\r\n"
	ERR_CHANNELISFULL    = ":%s 471 %s %s :Cannot join channel (+l)\r\n"
	ERR_UNKNOWNMODE      = ":%s 472 %s %s :is unknown mode char to me for %s\r\n"
	ERR_INVITEONLYCHAN   = ":%s 473 %s %s :Cannot join channel (+i)\r\n"
	ERR_BANNEDFROMCHAN   = ":%s 474 %s %s :Cannot join channel (+b)\r\n"
	ERR_BADCHANNELKEY    = ":%s 475 %s %s :Cannot join channel (+k)\r\n"
	ERR_NOPRIVILEGES     = ":%s 481 %s :Permission Denied - You're not an IRC operator\r\n"
	ERR_CHANOPRIVSNEEDED = ":%s 482 %s %s :You're not a channel operator\r\n"
	ERR_UMODEUNKNOWNFLAG = ":%s 501 %s :Unknown MODE flag\r\n"
	ERR_USERSDONTMATCH   = ":%s 502 %s :Can't change mode for other users\r\n"
	ERR_INVALIDKEY       = ":%s 525 %s %s :Key is not well-formed\r\n"
	RPL_MONONLINE        = ":%s 730 %s :%s\r\n"
	RPL_MONOFFLINE       = ":%s 731 %s :%s\r\n"
	RPL_MONLIST          = ":%s 732 %s :%s\r\n"
	RPL_ENDOFMONLIST     = ":%s 733 %s :End of MONITOR list\r\n"
	// ERR_MONLISTFULL      = ":%s 734 %s %v %v :Monitor list is full"

	RPL_LOGGEDIN    = ":%s 900 %s %s %s :You are now logged in as %s\r\n"
	RPL_LOGGEDOUT   = ":%s 901 %s %s :You are not logged out\r\n"
	ERR_NICKLOCKED  = ":%s 902 %s :You must use a nick assigned to you\r\n"
	RPL_SASLSUCCESS = ":%s 903 %s :SASL authentication successful\r\n"
	ERR_SASLFAIL    = ":%s 904 %s :SASL authentication failed\r\n"
	ERR_SASLTOOLONG = ":%s 905 %s :SASL message too long\r\n"
	ERR_SASLABORTED = ":%s 906 %s :SASL authentication aborted\r\n"
	ERR_SASLALREADY = ":%s 907 %s :You have already authenticated using SASL\r\n"
	RPL_SASLMECHS   = ":%s 908 %s %s :are available SASL mechanisms\r\n"
)

func (s *Server) writeReply(c *client.Client, format string, f ...interface{}) {
	args := make([]interface{}, 2+len(f))
	args[0] = s.Name
	args[1] = c.Id()
	copy(args[2:], f)
	fmt.Fprintf(c, format, args...)
}

func (s *Server) ERROR(c *client.Client, m string) {
	s.deleteClient(c.Nick)

	c.WriteMessage(msg.New(nil, "", "", "", "ERROR", []string{m}, true))
	c.Close()
}

func (s *Server) NOTICE(c *client.Client, m string) {
	c.WriteMessage(msg.New(nil, "", "", "", "NOTICE", []string{m}, true))
}

// given a channel, construct a NAMREPLY for all the members. if
// invisibles is true, include invisible members in the response; this
// should only be done if the requesting client is also a member of the
// channel
func constructNAMREPLY(c *channel.Channel, invisibles bool, multiPrefix bool, userhostInNames bool) (symbol string, members string) {
	symbol = "="
	if c.Secret {
		symbol = "@"
	}

	c.MembersLock.RLock()
	defer c.MembersLock.RUnlock()
	for _, v := range c.Members {
		// if not inluding invisible clients, and this client is invisible
		if !invisibles && v.Client.Is(client.Invisible) {
			continue
		}

		highest := v.HighestPrefix(multiPrefix)
		if highest != "" {
			members += highest
		}

		identifier := v.Nick
		if userhostInNames {
			identifier = v.String()
		}
		members += identifier + " "
	}
	return symbol, members[:len(members)-1]
}

var isupportTokens = func() []string {
	supported := []string{
		"BOT=b",
		"CASEMAPPING=ascii",
		"CHANLIMIT=#&:",
		"CHANMODES=beI,k,l,imnst",
		"ELIST=CMNTU",
		"MONITOR", // TODO: add a limit?
		// "STATUSMSG=~&@%+",
		"PREFIX=(qaohv)~&@%+",
		"WHOX",
		"UTF8ONLY",

		// TODO: honor the below values
		"AWAYLEN=200",
		"CHANNELLEN=64",
		"HOSTLEN=64",
		"KICKLEN=200",
		"MAXLIST=beI:25",
		"NICKLEN=30",
		"TOPICLEN=307",
		"USERLEN=18",
	}

	// try to get every line below 200 bytes, that seems like a good number
	lines := []string{}
	line := supported[0]
	for i := 1; i < len(supported); i++ {
		line += " " + supported[i]
		if len(line) > 200 {
			lines = append(lines, line)
			line = ""
		}
	}

	// if all supported params fit on one line
	if len(lines) == 0 {
		lines = append(lines, line)
	}

	return lines
}()

func whoreplyFlagsForClient(c *client.Client) string {
	flags := "H"
	if c.Is(client.Away) {
		flags = "G"
	}
	if c.Is(client.Bot) {
		flags += "b"
	}
	if c.Is(client.Op) {
		flags += "*"
	}
	return flags
}

func whoreplyFlagsForMember(m *channel.Member, multiPrefix bool) string {
	flags := whoreplyFlagsForClient(m.Client)
	if multiPrefix {
		return flags + m.HighestPrefix(true)
	}

	if m.Is(channel.Operator) {
		flags += "@"
	}
	if m.Is(channel.Voice) {
		flags += "+"
	}
	return flags
}
