package server

import (
	"fmt"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
)

const (
	RPL_WELCOME       = ":%s 001 %s :Welcome to the %s IRC Network %s"
	RPL_YOURHOST      = ":%s 002 %s :Your host is %s"
	RPL_CREATED       = ":%s 003 %s :This server was created %s"
	RPL_MYINFO        = ":%s 004 %s %s %s %s %s"
	RPL_ISUPPORT      = ":%s 005 %s %s :are supported by this server"
	RPL_UMODEIS       = ":%s 221 %s %s"
	RPL_LUSERCLIENT   = ":%s 251 %s :There are %d users and %d invisible on %d servers"
	RPL_LUSEROP       = ":%s 252 %s %d :operator(s) online"
	RPL_LUSERUNKNOWN  = ":%s 253 %s %d :unknown connection(s)"
	RPL_LUSERCHANNELS = ":%s 254 %s %d :channels formed"
	RPL_LUSERME       = ":%s 255 %s :I have %d clients and %d servers"
	RPL_AWAY          = ":%s 301 %s %s :%s"
	RPL_UNAWAY        = ":%s 305 %s :You are no longer marked as being away"
	RPL_NOWAWAY       = ":%s 306 %s :You have been marked as being away"
	RPL_WHOISUSER     = ":%s 311 %s %s %s %s * :%s"
	RPL_WHOISSERVER   = ":%s 312 %s %s %s :%s"
	RPL_WHOISOPERATOR = ":%s 313 %s %s :is an IRC operator"
	// RPL_WHOWASUSER       = ":%s 314 %s %s %s %s * %s"
	RPL_WHOISIDLE        = ":%s 317 %s %s %v %v :seconds idle, signon time"
	RPL_ENDOFWHOIS       = ":%s 318 %s :End of /WHOIS list"
	RPL_WHOISCHANNELS    = ":%s 319 %s %s%s"
	RPL_ENDOFWHO         = ":%s 315 %s %s :End of WHO list"
	RPL_LIST             = ":%s 322 %s %s %v :%s"
	RPL_LISTEND          = ":%s 323 %s :End of /LIST"
	RPL_CHANNELMODEIS    = ":%s 324 %s %s %s%s"
	RPL_NOTOPIC          = ":%s 331 %s %s :No topic is set"
	RPL_TOPIC            = ":%s 332 %s %s :%s"
	RPL_INVITING         = ":%s 341 %s %s"
	RPL_INVITELIST       = ":%s 346 %s %s %s"
	RPL_ENDOFINVITELIST  = ":%s 347 %s %s :End of channel invite list"
	RPL_EXCEPTLIST       = ":%s 348 %s %s %s"
	RPL_ENDOFEXCEPTLIST  = ":%s 349 %s %s :End of channel exception list"
	RPL_WHOREPLY         = ":%s 352 %s %s %s %s %s %s %s :0 %s"
	RPL_NAMREPLY         = ":%s 353 %s %s %s :%s"
	RPL_ENDOFNAMES       = ":%s 366 %s %s :End of /NAMES list"
	RPL_BANLIST          = ":%s 367 %s %s %s"
	RPL_ENDOFBANLIST     = ":%s 368 %s %s :End of channel ban list"
	RPL_MOTDSTART        = ":%s 375 %s :- %s Message of the Day -"
	RPL_MOTD             = ":%s 371 %s :%s"
	RPL_ENDOFMOTD        = ":%s 376 %s :End of /MOTD command"
	RPL_YOUREOPER        = ":%s 381 %s :You are now an IRC operator"
	RPL_REHASHING        = ":%s 382 $s %s :Rehashing"
	RPL_TIME             = ":%s 391 %s %s :%s"
	ERR_NOSUCHNICK       = ":%s 401 %s %s :No such nick/channel"
	ERR_NOSUCHCHANNEL    = ":%s 403 %s %s :No such channel"
	ERR_CANNOTSENDTOCHAN = ":%s 404 %s %s :Cannot send to channel"
	ERR_INVALIDCAPCMD    = ":%s 410 %s %s :Invalid CAP command"
	ERR_NORECIPIENT      = ":%s 411 %s :No recipient given (%s)"
	ERR_NOTEXTTOSEND     = ":%s 412 %s :No text to send"
	ERR_INPUTTOOLONG     = ":%s 417 %s :Input line was too long"
	ERR_UNKNOWNCOMMAND   = ":%s 421 %s %s :Unknown command"
	ERR_NOMOTD           = ":%s 422 %s :MOTD file is missing"
	ERR_NONICKNAMEGIVEN  = ":%s 431 %s :No nickname given"
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
)

func (s *Server) constructReply(clientId string, format string, f ...interface{}) string {
	args := make([]interface{}, 2+len(f))
	args[0] = s.Name
	args[1] = clientId
	copy(args[2:], f)
	return fmt.Sprintf(format+"\r\n", args...)
}

func (s *Server) numericReply(c *client.Client, format string, f ...interface{}) {
	args := make([]interface{}, 2+len(f))
	args[0] = s.Name
	args[1] = c.Id()
	copy(args[2:], f)
	fmt.Fprintf(c, format+"\r\n", args...)
}

func (s *Server) ERROR(c *client.Client, msg string) {
	fmt.Fprintf(c, "ERROR :%s\r\n", msg)
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
			highest := v.HighestPrefix()
			if highest != -1 {
				members += string(highest)
			}
		}
		members += k + " "
	}
	return symbol, members[0 : len(members)-1]
}

// TODO: actually honor these values
func constructISUPPORT() []string {
	supported := []string{
		"AWAYLEN=200",
		"CASEMAPPING=ascii",
		"CHANLIMIT=#&:",
		"CHANNELLEN=64",
		"ELIST=N",
		"HOSTLEN=64",
		"KICKLEN=200",
		"MAXLIST=beI:25",
		"NICKLEN=30",
		"STATUSMSG=~&@%+",
		"TOPICLEN=307",
		"USERLEN=18",
	}

	// try to get every line below 200 bytes, that seems like a good number
	lines := []string{}
	line := ""
	for i := 0; i < len(supported); i++ {
		line += supported[i] + " "
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
}
