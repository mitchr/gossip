package server

import (
	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

var (
	RPL_WELCOME          = msg.New(nil, "", "", "", "001", []string{"%s", "Welcome to the %s IRC Network %s"}, true)
	RPL_YOURHOST         = msg.New(nil, "", "", "", "002", []string{"%s", "Your host is %s"}, true)
	RPL_CREATED          = msg.New(nil, "", "", "", "003", []string{"%s", "This server was created %s"}, true)
	RPL_MYINFO           = msg.New(nil, "", "", "", "004", []string{"%s", "%s", "%s", "%s", "%s"}, false)
	RPL_ISUPPORT         = msg.New(nil, "", "", "", "005", []string{"%s", "%s", "are supported by this server"}, true)
	RPL_UMODEIS          = msg.New(nil, "", "", "", "221", []string{"%s", "%s"}, false)
	RPL_LUSERCLIENT      = msg.New(nil, "", "", "", "251", []string{"%s", "There are %d users and %d invisible on %d servers"}, true)
	RPL_LUSEROP          = msg.New(nil, "", "", "", "252", []string{"%s", "%d", "operator(s) online"}, true)
	RPL_LUSERUNKNOWN     = msg.New(nil, "", "", "", "253", []string{"%s", "%d", "unknown connection(s)"}, true)
	RPL_LUSERCHANNELS    = msg.New(nil, "", "", "", "254", []string{"%s", "%d", "channels formed"}, true)
	RPL_LUSERME          = msg.New(nil, "", "", "", "255", []string{"%s", "I have %d clients and %d servers"}, true)
	RPL_LOCALUSERS       = msg.New(nil, "", "", "", "265", []string{"%s", "%v", "%v", "Current local users %v, max %v"}, true)
	RPL_GLOBALUSERS      = msg.New(nil, "", "", "", "266", []string{"%s", "%v", "%v", "Current global users %v, max %v"}, true)
	RPL_WHOISCERTFP      = msg.New(nil, "", "", "", "276", []string{"%s", "%s", "has client certificate fingerprint %s"}, true)
	RPL_AWAY             = msg.New(nil, "", "", "", "301", []string{"%s", "%s", "%s"}, true)
	RPL_USERHOST         = msg.New(nil, "", "", "", "302", []string{"%s", "%s"}, true)
	RPL_UNAWAY           = msg.New(nil, "", "", "", "305", []string{"%s", "You are no longer marked as being away"}, true)
	RPL_NOWAWAY          = msg.New(nil, "", "", "", "306", []string{"%s", "You have been marked as being away"}, true)
	RPL_WHOISUSER        = msg.New(nil, "", "", "", "311", []string{"%s", "%s", "%s", "%s", "*", "%s"}, true)
	RPL_WHOISSERVER      = msg.New(nil, "", "", "", "312", []string{"%s", "%s", "%s", "%s"}, true)
	RPL_WHOISOPERATOR    = msg.New(nil, "", "", "", "313", []string{"%s", "%s", "is an IRC operator"}, true)
	RPL_WHOWASUSER       = msg.New(nil, "", "", "", "314", []string{"%s", "%s", "%s", "%s", "*", "%s"}, false)
	RPL_WHOISIDLE        = msg.New(nil, "", "", "", "317", []string{"%s", "%s", "%v", "%v", "seconds idle, signon time"}, true)
	RPL_ENDOFWHOIS       = msg.New(nil, "", "", "", "318", []string{"%s", "%s", "End of /WHOIS list"}, true)
	RPL_WHOISCHANNELS    = msg.New(nil, "", "", "", "319", []string{"%s", "%s%s"}, false)
	RPL_ENDOFWHO         = msg.New(nil, "", "", "", "315", []string{"%s", "%s", "End of WHO list"}, true)
	RPL_LIST             = msg.New(nil, "", "", "", "322", []string{"%s", "%s", "%v", "%s"}, true)
	RPL_LISTEND          = msg.New(nil, "", "", "", "323", []string{"%s", "End of /LIST"}, true)
	RPL_CHANNELMODEIS    = msg.New(nil, "", "", "", "324", []string{"%s", "%s", "%s%s"}, false)
	RPL_CREATIONTIME     = msg.New(nil, "", "", "", "329", []string{"%s", "%s", "%s"}, false)
	RPL_WHOISACCOUNT     = msg.New(nil, "", "", "", "330", []string{"%s", "%s", "%s", "is logged in as"}, true)
	RPL_NOTOPIC          = msg.New(nil, "", "", "", "331", []string{"%s", "%s", "No topic is set"}, true)
	RPL_TOPIC            = msg.New(nil, "", "", "", "332", []string{"%s", "%s", "%s"}, true)
	RPL_TOPICWHOTIME     = msg.New(nil, "", "", "", "333", []string{"%s", "%s", "%s", "%v"}, false)
	RPL_WHOISBOT         = msg.New(nil, "", "", "", "335", []string{"%s", "%s", "bot"}, true)
	RPL_INVITELIST       = msg.New(nil, "", "", "", "336", []string{"%s", "%s"}, false)
	RPL_ENDOFINVITELIST  = msg.New(nil, "", "", "", "337", []string{"%s", "End of /INVITE list"}, true)
	RPL_INVITING         = msg.New(nil, "", "", "", "341", []string{"%s", "%s", "%s"}, false)
	RPL_INVEXLIST        = msg.New(nil, "", "", "", "346", []string{"%s", "%s", "%s"}, false)
	RPL_ENFOFINVEXLIST   = msg.New(nil, "", "", "", "347", []string{"%s", "%s", "End of channel invite list"}, true)
	RPL_EXCEPTLIST       = msg.New(nil, "", "", "", "348", []string{"%s", "%s", "%s"}, false)
	RPL_ENDOFEXCEPTLIST  = msg.New(nil, "", "", "", "349", []string{"%s", "%s", "End of channel exception list"}, true)
	RPL_WHOREPLY         = msg.New(nil, "", "", "", "352", []string{"%s", "%s", "%s", "%s", "%s", "%s", "%s", "0 %s"}, true)
	RPL_NAMREPLY         = msg.New(nil, "", "", "", "353", []string{"%s", "%s", "%s", "%s"}, true)
	RPL_WHOSPCRPL        = msg.New(nil, "", "", "", "354", []string{"%s", "%s"}, false)
	RPL_ENDOFNAMES       = msg.New(nil, "", "", "", "366", []string{"%s", "%s", "End of /NAMES list"}, true)
	RPL_BANLIST          = msg.New(nil, "", "", "", "367", []string{"%s", "%s", "%s"}, false)
	RPL_ENDOFBANLIST     = msg.New(nil, "", "", "", "368", []string{"%s", "%s", "End of channel ban list"}, true)
	RPL_ENDOFWHOWAS      = msg.New(nil, "", "", "", "369", []string{"%s", "%s", "End of WHOWAS"}, true)
	RPL_MOTDSTART        = msg.New(nil, "", "", "", "375", []string{"%s", "- %s Message of the Day -"}, true)
	RPL_INFO             = msg.New(nil, "", "", "", "371", []string{"%s", "%s"}, true)
	RPL_MOTD             = msg.New(nil, "", "", "", "372", []string{"%s", "%s"}, true)
	RPL_ENDOFINFO        = msg.New(nil, "", "", "", "374", []string{"%s", "End of INFO list"}, true)
	RPL_ENDOFMOTD        = msg.New(nil, "", "", "", "376", []string{"%s", "End of /MOTD command"}, true)
	RPL_YOUREOPER        = msg.New(nil, "", "", "", "381", []string{"%s", "You are now an IRC operator"}, true)
	RPL_REHASHING        = msg.New(nil, "", "", "", "382", []string{"%s", "%s", "Rehashing"}, true)
	RPL_TIME             = msg.New(nil, "", "", "", "391", []string{"%s", "%s", "%s"}, true)
	ERR_NOSUCHNICK       = msg.New(nil, "", "", "", "401", []string{"%s", "%s", "No such nick/channel"}, true)
	ERR_NOSUCHCHANNEL    = msg.New(nil, "", "", "", "403", []string{"%s", "%s", "No such channel"}, true)
	ERR_CANNOTSENDTOCHAN = msg.New(nil, "", "", "", "404", []string{"%s", "%s", "Cannot send to channel"}, true)
	ERR_WASNOSUCHNICK    = msg.New(nil, "", "", "", "406", []string{"%s", "%s", "There was no such nickname"}, true)
	ERR_INVALIDCAPCMD    = msg.New(nil, "", "", "", "410", []string{"%s", "%s", "Invalid CAP command"}, true)
	ERR_NORECIPIENT      = msg.New(nil, "", "", "", "411", []string{"%s", "No recipient given (%s)"}, true)
	ERR_NOTEXTTOSEND     = msg.New(nil, "", "", "", "412", []string{"%s", "No text to send"}, true)
	ERR_INPUTTOOLONG     = msg.New(nil, "", "", "", "417", []string{"%s", "Input line was too long"}, true)
	ERR_UNKNOWNCOMMAND   = msg.New(nil, "", "", "", "421", []string{"%s", "%s", "Unknown command"}, true)
	ERR_NOMOTD           = msg.New(nil, "", "", "", "422", []string{"%s", "MOTD file is missing"}, true)
	ERR_NONICKNAMEGIVEN  = msg.New(nil, "", "", "", "431", []string{"%s", "No nickname given"}, true)
	ERR_ERRONEUSNICKNAME = msg.New(nil, "", "", "", "432", []string{"%s", "Erroneous nickname"}, true)
	ERR_NICKNAMEINUSE    = msg.New(nil, "", "", "", "433", []string{"%s", "%s", "Nickname is already in use"}, true)
	ERR_USERNOTINCHANNEL = msg.New(nil, "", "", "", "441", []string{"%s", "%s", "%s", "They aren't on that channel"}, true)
	ERR_NOTONCHANNEL     = msg.New(nil, "", "", "", "442", []string{"%s", "%s", "You're not on that channel"}, true)
	ERR_USERONCHANNEL    = msg.New(nil, "", "", "", "443", []string{"%s", "%s", "%s", "is already on channel"}, true)
	ERR_NOTREGISTERED    = msg.New(nil, "", "", "", "451", []string{"%s", "You have not registered"}, true)
	ERR_NEEDMOREPARAMS   = msg.New(nil, "", "", "", "461", []string{"%s", "%s", "Not enough parameters"}, true)
	ERR_ALREADYREGISTRED = msg.New(nil, "", "", "", "462", []string{"%s", "You may not reregister"}, true)
	ERR_PASSWDMISMATCH   = msg.New(nil, "", "", "", "464", []string{"%s", "Password Incorrect"}, true)
	ERR_CHANNELISFULL    = msg.New(nil, "", "", "", "471", []string{"%s", "%s", "Cannot join channel (+l)"}, true)
	ERR_UNKNOWNMODE      = msg.New(nil, "", "", "", "472", []string{"%s", "%s", "is unknown mode char to me for %s"}, true)
	ERR_INVITEONLYCHAN   = msg.New(nil, "", "", "", "473", []string{"%s", "%s", "Cannot join channel (+i)"}, true)
	ERR_BANNEDFROMCHAN   = msg.New(nil, "", "", "", "474", []string{"%s", "%s", "Cannot join channel (+b)"}, true)
	ERR_BADCHANNELKEY    = msg.New(nil, "", "", "", "475", []string{"%s", "%s", "Cannot join channel (+k)"}, true)
	ERR_NOPRIVILEGES     = msg.New(nil, "", "", "", "481", []string{"%s", "Permission Denied - You're not an IRC operator"}, true)
	ERR_CHANOPRIVSNEEDED = msg.New(nil, "", "", "", "482", []string{"%s", "%s", "You're not a channel operator"}, true)
	ERR_UMODEUNKNOWNFLAG = msg.New(nil, "", "", "", "501", []string{"%s", "Unknown MODE flag"}, true)
	ERR_USERSDONTMATCH   = msg.New(nil, "", "", "", "502", []string{"%s", "Can't change mode for other users"}, true)
	ERR_INVALIDKEY       = msg.New(nil, "", "", "", "525", []string{"%s", "%s", "Key is not well-formed"}, true)
	RPL_MONONLINE        = msg.New(nil, "", "", "", "730", []string{"%s", "%s"}, true)
	RPL_MONOFFLINE       = msg.New(nil, "", "", "", "731", []string{"%s", "%s"}, true)
	RPL_MONLIST          = msg.New(nil, "", "", "", "732", []string{"%s", "%s"}, true)
	RPL_ENDOFMONLIST     = msg.New(nil, "", "", "", "733", []string{"%s", "End of MONITOR list"}, true)
	// ERR_MONLISTFULL      = ":%s 734 %s %v %v :Monitor list is full"

	RPL_LOGGEDIN    = msg.New(nil, "", "", "", "900", []string{"%s", "%s", "%s", "You are now logged in as %s"}, true)
	RPL_LOGGEDOUT   = msg.New(nil, "", "", "", "901", []string{"%s", "%s", "You are not logged out"}, true)
	ERR_NICKLOCKED  = msg.New(nil, "", "", "", "902", []string{"%s", "You must use a nick assigned to you"}, true)
	RPL_SASLSUCCESS = msg.New(nil, "", "", "", "903", []string{"%s", "SASL authentication successful"}, true)
	ERR_SASLFAIL    = msg.New(nil, "", "", "", "904", []string{"%s", "SASL authentication failed"}, true)
	ERR_SASLTOOLONG = msg.New(nil, "", "", "", "905", []string{"%s", "SASL message too long"}, true)
	ERR_SASLABORTED = msg.New(nil, "", "", "", "906", []string{"%s", "SASL authentication aborted"}, true)
	ERR_SASLALREADY = msg.New(nil, "", "", "", "907", []string{"%s", "You have already authenticated using SASL"}, true)
	RPL_SASLMECHS   = msg.New(nil, "", "", "", "908", []string{"%s", "%s", "are available SASL mechanisms"}, true)
)

func (s *Server) writeReply(c *client.Client, msg *msg.Message, f ...interface{}) {
	c.WriteMessage(prepMessage(msg, s.Name, c.Id(), f...))
}

func prepMessage(m *msg.Message, serverName, nick string, f ...interface{}) *msg.Message {
	mCopy := m.Format(append([]interface{}{nick}, f...)...)
	mCopy.Nick = serverName
	return mCopy
}

func (s *Server) ERROR(c *client.Client, m string) {
	s.deleteClient(c.Nick)

	c.WriteMessage(msg.New(nil, "", "", "", "ERROR", []string{m}, true))
	c.Close()
}

func (s *Server) NOTICE(c *client.Client, m string) msg.Msg {
	return msg.New(nil, "", "", "", "NOTICE", []string{m}, true)
}

// given a channel, construct a NAMREPLY for all the members. if
// invisibles is true, include invisible members in the response; this
// should only be done if the requesting client is also a member of the
// channel
func constructNAMREPLY(ch *channel.Channel, invisibles bool, multiPrefix bool, userhostInNames bool) (symbol string, members string) {
	symbol = "="
	if ch.Secret {
		symbol = "@"
	}

	ch.ForAllMembers(func(m *channel.Member) {
		// if not inluding invisible clients, and this client is invisible
		if !invisibles && m.Client.Is(client.Invisible) {
			return
		}

		highest := m.HighestPrefix(multiPrefix)
		if highest != "" {
			members += highest
		}

		identifier := m.Nick
		if userhostInNames {
			identifier = m.String()
		}
		members += identifier + " "
	})
	return symbol, members[:len(members)-1]
}

var isupportTokens = func() []string {
	supported := []string{
		"BOT=b",
		"CASEMAPPING=ascii",
		"CHANLIMIT=#&:",
		"CHANMODES=beI,k,l,imnst",
		"ELIST=CMNTU",
		"INVEX=I",
		"MONITOR", // TODO: add a limit?
		// "STATUSMSG=~&@%+",
		"PREFIX=(qaohv)~&@%+",
		"WHOX",
		"UTF8ONLY",
		"TARGMAX=KICK:,NAMES:,PRIVMSG:,WHOIS:,WHOWAS:",

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
