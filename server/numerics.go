package server

import (
	"fmt"

	"github.com/mitchr/gossip/client"
)

const (
	RPL_WELCOME          = ":%s 001 %s :Welcome to the Internet Relay Network %s"
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
	RPL_CHANNELMODEIS    = ":%s 324 %s %s %s"
	RPL_NOTOPIC          = ":%s 331 %s %s :No topic is set"
	RPL_TOPIC            = ":%s 332 %s %s :%s"
	RPL_INVITING         = ":%s 341 %s %s"
	RPL_NAMREPLY         = ":%s 353 %s %s %s :$s"
	RPL_ENDOFNAMES       = ":%s 366 %s %s :End of /NAMES list"
	RPL_MOTDSTART        = ":%s 375 %s :- %s Message of the Day -"
	RPL_MOTD             = ":%s 371 %s :%s"
	RPL_ENDOFMOTD        = ":%s 376 %s :End of /MOTD command"
	ERR_NOSUCHNICK       = ":%s 401 %s %s :No such nick/channel"
	ERR_NOSUCHCHANNEL    = ":%s 403 %s %s :No such channel"
	ERR_CANNOTSENDTOCHAN = ":%s 404 %s %s :Cannot send to channel"
	ERR_NORECIPIENT      = ":%s 411 %s :No recipient given (%s)"
	ERR_NOTEXTTOSEND     = ":%s 412 %s :No text to send"
	ERR_NOTONCHANNEL     = ":%s 442 %s %s :You're not on that channel"
	ERR_UNKNOWNCOMMAND   = ":%s 421 %s %s :Unknown command"
	ERR_NONICKNAMEGIVEN  = ":%s 431 %s :No nickname given"
	ERR_NICKNAMEINUSE    = ":%s 433 %s %s :Nickname is already in use"
	ERR_USERNOTINCHANNEL = ":%s 441 %s %s %s :They aren't on that channel"
	ERR_USERONCHANNEL    = ":%s 443 %s %s %s :is already on channel"
	ERR_NEEDMOREPARAMS   = ":%s 461 %s %s :Not enough parameters"
	ERR_ALREADYREGISTRED = ":%s 462 %s :You may not reregister"
	ERR_PASSWDMISMATCH   = ":%s 464 %s :Password Incorrect"
	ERR_CHANNELISFULL    = ":%s 471 %s %s :Cannot join channel (+l)"
	ERR_UNKNOWNMODE      = ":%s 472 %s %s :is unknown mode char to me for %s"
	ERR_BANNEDFROMCHAN   = ":%s 474 %s %s :Cannot join channel (+b)"
	ERR_INVITEONLYCHAN   = ":%s 473 %s %s :Cannot join channel (+i)"
	ERR_BADCHANNELKEY    = ":%s 475 %s %s :Cannot join channel (+k)"
	ERR_CHANOPRIVSNEEDED = ":%s 482 %s %s :You're not channel operators"
	ERR_UMODEUNKNOWNFLAG = ":%s 501 %s :Unknown MODE flag"
	ERR_USERSDONTMATCH   = ":%s 502 %s :Can't change mode for other users"
)

func (s *Server) numericReply(c *client.Client, format string, f ...interface{}) {
	args := []interface{}{s.listener.Addr(), c.Nick}
	args = append(args, f...)
	c.Write(fmt.Sprintf(format, args...))
}

func (s *Server) ERROR(c *client.Client, msg string) {
	c.Write(fmt.Sprintf("ERROR :%s", msg))
}
