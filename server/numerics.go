package server

import (
	"fmt"
	"io"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
)

const (
	RPL_WELCOME          = ":%s 001 %s :Welcome to the %s IRC Network %s"
	RPL_YOURHOST         = ":%s 002 %s :Your host is %s"
	RPL_CREATED          = ":%s 003 %s :This server was created %s"
	RPL_MYINFO           = ":%s 004 %s %s %s %s %s"
	RPL_ISUPPORT         = ":%s 005 %s %s :are supported by this server"
	RPL_UMODEIS          = ":%s 221 %s %s"
	RPL_LUSERCLIENT      = ":%s 251 %s :There are %d users and %d invisible on %d servers"
	RPL_LUSEROP          = ":%s 252 %s %d :operator(s) online"
	RPL_LUSERUNKNOWN     = ":%s 253 %s %d :unknown connection(s)"
	RPL_LUSERCHANNELS    = ":%s 254 %s %d :channels formed"
	RPL_LUSERME          = ":%s 255 %s :I have %d clients and %d servers"
	RPL_LOCALUSERS       = ":%s 265 %s %v %v :Current local users %v, max %v"
	RPL_GLOBALUSERS      = ":%s 266 %s %v %v :Current global users %v, max %v"
	RPL_WHOISCERTFP      = ":%s 276 %s %s :has client certificate fingerprint %s"
	RPL_AWAY             = ":%s 301 %s %s :%s"
	RPL_USERHOST         = ":%s 302 %s :%s"
	RPL_UNAWAY           = ":%s 305 %s :You are no longer marked as being away"
	RPL_NOWAWAY          = ":%s 306 %s :You have been marked as being away"
	RPL_WHOISUSER        = ":%s 311 %s %s %s %s * :%s"
	RPL_WHOISSERVER      = ":%s 312 %s %s %s :%s"
	RPL_WHOISOPERATOR    = ":%s 313 %s %s :is an IRC operator"
	RPL_WHOWASUSER       = ":%s 314 %s %s %s %s * %s"
	RPL_WHOISIDLE        = ":%s 317 %s %s %v %v :seconds idle, signon time"
	RPL_ENDOFWHOIS       = ":%s 318 %s %s :End of /WHOIS list"
	RPL_WHOISCHANNELS    = ":%s 319 %s %s%s"
	RPL_ENDOFWHO         = ":%s 315 %s %s :End of WHO list"
	RPL_LIST             = ":%s 322 %s %s %v :%s"
	RPL_LISTEND          = ":%s 323 %s :End of /LIST"
	RPL_CHANNELMODEIS    = ":%s 324 %s %s %s%s"
	RPL_WHOISACCOUNT     = ":%s 330 %s %s %s :is logged in as"
	RPL_NOTOPIC          = ":%s 331 %s %s :No topic is set"
	RPL_TOPIC            = ":%s 332 %s %s :%s"
	RPL_TOPICWHOTIME     = ":%s 333 %s %s %s %v"
	RPL_INVITING         = ":%s 341 %s %s %s"
	RPL_INVITELIST       = ":%s 346 %s %s %s"
	RPL_ENDOFINVITELIST  = ":%s 347 %s %s :End of channel invite list"
	RPL_EXCEPTLIST       = ":%s 348 %s %s %s"
	RPL_ENDOFEXCEPTLIST  = ":%s 349 %s %s :End of channel exception list"
	RPL_WHOREPLY         = ":%s 352 %s %s %s %s %s %s %s :0 %s"
	RPL_NAMREPLY         = ":%s 353 %s %s %s :%s"
	RPL_WHOSPCRPL        = ":%s 354 %s %s"
	RPL_ENDOFNAMES       = ":%s 366 %s %s :End of /NAMES list"
	RPL_BANLIST          = ":%s 367 %s %s %s"
	RPL_ENDOFBANLIST     = ":%s 368 %s %s :End of channel ban list"
	RPL_ENDOFWHOWAS      = ":%s 369 %s %s :End of WHOWAS"
	RPL_MOTDSTART        = ":%s 375 %s :- %s Message of the Day -"
	RPL_INFO             = ":%s 371 %s :%s"
	RPL_MOTD             = ":%s 372 %s :%s"
	RPL_ENDOFINFO        = ":%s 374 %s :End of INFO list"
	RPL_ENDOFMOTD        = ":%s 376 %s :End of /MOTD command"
	RPL_YOUREOPER        = ":%s 381 %s :You are now an IRC operator"
	RPL_REHASHING        = ":%s 382 %s %s :Rehashing"
	RPL_TIME             = ":%s 391 %s %s :%s"
	ERR_NOSUCHNICK       = ":%s 401 %s %s :No such nick/channel"
	ERR_NOSUCHCHANNEL    = ":%s 403 %s %s :No such channel"
	ERR_CANNOTSENDTOCHAN = ":%s 404 %s %s :Cannot send to channel"
	ERR_WASNOSUCHNICK    = ":%s 406 %s %s :There was no such nickname"
	ERR_INVALIDCAPCMD    = ":%s 410 %s %s :Invalid CAP command"
	ERR_NORECIPIENT      = ":%s 411 %s :No recipient given (%s)"
	ERR_NOTEXTTOSEND     = ":%s 412 %s :No text to send"
	ERR_INPUTTOOLONG     = ":%s 417 %s :Input line was too long"
	ERR_UNKNOWNCOMMAND   = ":%s 421 %s %s :Unknown command"
	ERR_NOMOTD           = ":%s 422 %s :MOTD file is missing"
	ERR_NONICKNAMEGIVEN  = ":%s 431 %s :No nickname given"
	ERR_ERRONEUSNICKNAME = ":%s 432 %s :Erroneous nickname"
	ERR_NICKNAMEINUSE    = ":%s 433 %s %s :Nickname is already in use"
	ERR_USERNOTINCHANNEL = ":%s 441 %s %s %s :They aren't on that channel"
	ERR_NOTONCHANNEL     = ":%s 442 %s %s :You're not on that channel"
	ERR_USERONCHANNEL    = ":%s 443 %s %s %s :is already on channel"
	ERR_NEEDMOREPARAMS   = ":%s 461 %s %s :Not enough parameters"
	ERR_ALREADYREGISTRED = ":%s 462 %s :You may not reregister"
	ERR_PASSWDMISMATCH   = ":%s 464 %s :Password Incorrect"
	ERR_CHANNELISFULL    = ":%s 471 %s %s :Cannot join channel (+l)"
	ERR_UNKNOWNMODE      = ":%s 472 %s %s :is unknown mode char to me for %s"
	ERR_BANNEDFROMCHAN   = ":%s 474 %s %s :Cannot join channel (+b)"
	ERR_INVITEONLYCHAN   = ":%s 473 %s %s :Cannot join channel (+i)"
	ERR_BADCHANNELKEY    = ":%s 475 %s %s :Cannot join channel (+k)"
	ERR_NOPRIVILEGES     = ":%s 481 %s :Permission Denied - You're not an IRC operator"
	ERR_CHANOPRIVSNEEDED = ":%s 482 %s %s :You're not a channel operator"
	ERR_UMODEUNKNOWNFLAG = ":%s 501 %s :Unknown MODE flag"
	ERR_USERSDONTMATCH   = ":%s 502 %s :Can't change mode for other users"
	ERR_INVALIDKEY       = ":%s 525 %s %s :Key is not well-formed"

	RPL_LOGGEDIN    = ":%s 900 %s %s %s :You are now logged in as %s"
	RPL_LOGGEDOUT   = ":%s 901 %s %s :You are not logged out"
	ERR_NICKLOCKED  = ":%s 902 %s :You must use a nick assigned to you"
	RPL_SASLSUCCESS = ":%s 903 %s :SASL authentication successful"
	ERR_SASLFAIL    = ":%s 904 %s :SASL authentication failed"
	ERR_SASLTOOLONG = ":%s 905 %s :SASL message too long"
	ERR_SASLABORTED = ":%s 906 %s :SASL authentication aborted"
	ERR_SASLALREADY = ":%s 907 %s :You have already authenticated using SASL"
	RPL_SASLMECHS   = ":%s 908 %s %s :are available SASL mechanisms"
)

func (s *Server) writeReply(buf io.Writer, clientId string, format string, f ...interface{}) {
	args := make([]interface{}, 2+len(f))
	args[0] = s.Name
	args[1] = clientId
	copy(args[2:], f)
	fmt.Fprintf(buf, format, args...)
}

func (s *Server) ERROR(c *client.Client, msg string) {
	fmt.Fprintf(c, "ERROR :%s", msg)
	c.Flush()
	c.Close()
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
		"CASEMAPPING=ascii",
		"CHANLIMIT=#&:",
		"ELIST=M",
		"STATUSMSG=~&@%+",
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
