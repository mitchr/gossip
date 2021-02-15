package server

const (
	RPL_WELCOME  = ":%s 001 %s :Welcome to the Internet Relay Network %s\r\n"
	RPL_YOURHOST = ":%s 002 %s :Your host is %s\r\n"
	RPL_CREATED  = ":%s 003 %s :This server was created %s\r\n"
	RPL_MYINFO   = "004"
	RPL_ISUPPORT = "005"

	RPL_LUSERCLIENT   = "251"
	RPL_LUSEROP       = "252"
	RPL_LUSERUNKNOWN  = "253"
	RPL_LUSERCHANNELS = "254"
	RPL_LUSERME       = "255"

	ERR_UNKNOWNCOMMAND   = ":%s 421 %s %s :Unknown command"
	ERR_NONICKNAMEGIVEN  = ":%s 431 %s :No nickname given"
	ERR_NICKNAMEINUSE    = ":%s 433 %s %s :Nickname is already in use"
	ERR_NEEDMOREPARAMS   = ":%s 461 %s %s :Not enough parameters"
	ERR_ALREADYREGISTRED = ":%s 462 %s :You may not reregister\r\n"
)
