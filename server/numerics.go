package server

import (
	"fmt"

	"github.com/mitchr/gossip/client"
)

const (
	RPL_WELCOME          = ":%s 001 %s :Welcome to the Internet Relay Network %s\r\n"
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
	RPL_NOTOPIC          = ":%s 331 %s %s :No topic is set\r\n"
	RPL_TOPIC            = ":%s 332 %s %s :%s\r\n"
	RPL_NAMREPLY         = ":%s 353 %s %s %s :$s\r\n"
	RPL_ENDOFNAMES       = ":%s 366 %s %s :End of /NAMES list\r\n"
	RPL_MOTDSTART        = ":%s 375 %s :- %s Message of the Day -\r\n"
	RPL_MOTD             = ":%s 371 %s :%s\r\n"
	RPL_ENDOFMOTD        = ":%s 376 %s :End of /MOTD command\r\n"
	ERR_NOSUCHNICK       = ":%s 401 %s %s :No such nick/channel\r\n"
	ERR_NOSUCHCHANNEL    = ":%s 403 %s %s :No such channel\r\n"
	ERR_NORECIPIENT      = ":%s 411 %s :No recipient given (%s)\r\n"
	ERR_NOTEXTTOSEND     = ":%s 412 %s :No text to send\r\n"
	ERR_NOTONCHANNEL     = ":%s 442 %s %s :You're not on that channel\r\n"
	ERR_UNKNOWNCOMMAND   = ":%s 421 %s %s :Unknown command\r\n"
	ERR_NONICKNAMEGIVEN  = ":%s 431 %s :No nickname given\r\n"
	ERR_NICKNAMEINUSE    = ":%s 433 %s %s :Nickname is already in use\r\n"
	ERR_NEEDMOREPARAMS   = ":%s 461 %s %s :Not enough parameters\r\n"
	ERR_ALREADYREGISTRED = ":%s 462 %s :You may not reregister\r\n"
	ERR_PASSWDMISMATCH   = ":%s 464 %s :Password Incorrect\r\n"
	ERR_UMODEUNKNOWNFLAG = ":%s 501 %s :Unknown MODE flag\r\n"
	ERR_USERSDONTMATCH   = ":%s 502 %s :Can't change mode for other users\r\n"
)

func (s *Server) numericReply(c *client.Client, format string, f ...interface{}) {
	args := []interface{}{s.Listener.Addr(), c.Nick}
	args = append(args, f...)
	c.Write(fmt.Sprintf(format, args...))
}

func (s *Server) ERROR(c *client.Client, msg string) {
	c.Write(fmt.Sprintf("ERROR :%s\r\n", msg))
}
