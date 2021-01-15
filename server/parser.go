package server

import (
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/mitchr/gossip/client"
)

// type tokenType int
// type token struct {
// 	tType tokenType
// 	value string
// }
//
// const (
// 	// associated with tags
// 	tags tokenType = iota
// 	tag
// 	key
// 	escapedVal
// 	vendor
//
// 	source
// 	command
//
// 	// associated with parameters
// 	parameters
// 	nospcrlfcl
// 	middle
// 	trailing
// )

// Parse and if necessary, execute a message from the given client
func (s *Server) Parse(msg []byte, c *client.Client) error {
	// allow sending newline characters by themselves
	if msg[0] == '\r' && msg[1] == '\n' {
		return nil
	}

	// some clients like telnet might send an ASCII 4 (EOT, end of transaction) when closing, in which case they should be disconnected
	if msg[0] == 4 {
		return io.EOF
	}

	// fmt.Printf("msg length: %v\nmsg bytes: %v\nmsg: %s\n", len(msg), msg, string(msg))
	fmt.Println("msg:", string(msg))

	// if message does not end with \r\n, reject
	if msg[len(msg)-2] != '\r' && msg[len(msg)-1] != '\n' {
		// fmt.Println(msg[len(msg)-2], msg[len(msg)-1])
		return errors.New("ill-formed message: need CRLF line ending")
	} else {
		// trim '\r\n' off end
		msg = msg[:len(msg)-2]
	}

	pos := 0
	splitByWhitespace := strings.Split(string(msg), " ")

	switch splitByWhitespace[0][0] {
	// first element was a tag
	// second element could be source
	case byte('@'):
		parseTags(splitByWhitespace[pos])
		if len(splitByWhitespace) == 1 {
			return errors.New("message too short: missing source or command")
		}
		if splitByWhitespace[1][0] == ':' {
			pos++
			parseSource(splitByWhitespace[pos])
		}
	// first element was a source
	case byte(':'):
		parseSource(splitByWhitespace[pos])
		pos++

	// if there was no source or tags, then the source is assumed to just be the nicknam
	default:
		// client may not have a registered nickname at this point, so just call them 'you'?
		if c.Nick == "" {
			parseSource(":you")
		} else {
			parseSource(":" + c.Nick)
		}
	}

	// determine command name
	// if there are arguments, they will be handled now
	err := s.parseCommand(splitByWhitespace[pos:], c)
	if err != nil {
		c.Write(err)
		fmt.Println("wrote error to client")
	}
	return nil
}

func parseTags(tags string) map[string]string {
	// remove beginning '@'
	tags = tags[1:]

	// split string by semicolor
	splitBySemi := strings.Split(tags, ";")
	var tagMap = make(map[string]string)
	for i := 0; i < len(splitBySemi); i++ {
		splitByEq := strings.Split(splitBySemi[i], "=")
		// if key is given with no value
		if len(splitByEq) == 1 {
			tagMap[splitByEq[0]] = ""
		} else {
			tagMap[splitByEq[0]] = splitByEq[1]
		}
	}

	fmt.Println(tagMap)
	return tagMap
}

// returns nickname, user, and hostname of sender
func parseSource(source string) (string, string, string) {
	// trim ':' from beginning\
	source = source[1:]
	sourceInfo := strings.Split(source, "!")

	nick := ""
	user := ""
	host := ""
	loc := 0

	// atleast there is a nick and a hostname
	if len(sourceInfo) == 2 {
		nick = sourceInfo[0]
		loc = 1
	}

	// check if user is included in hostname
	addr := strings.Split(sourceInfo[loc], "@")

	// if len == 2, then both a user and host are provided
	if len(addr) == 2 {
		user = addr[0]
		host = addr[1]
	} else { // else just host was given
		host = addr[0]
	}

	return nick, user, host
}

func (s *Server) parseCommand(com []string, c *client.Client) error {
	if len(com) == 0 {
		return errors.New("missing command\r\n")
	}

	pos := 0
	// first element is command
	switch com[0] {
	case "CAP":
	case "NICK":
		// look at next argument
		pos++
		if pos > len(com)-1 {
			return s.numericReply(c, 433, "No nickname given")
		}

		// if nickname is already in use, send back error
		if s.Clients.SearchNick(com[1]) != nil {
			return s.numericReply(c, 433, "Nickname is already in use")
		}

		c.Nick = com[1]
		fmt.Println("registered nick:", com[1])
		s.endRegistration(c)
	case "USER":
		// TODO: Ident Protocol

		if c.Registered {
			return s.numericReply(c, 462, "You may not reregister")
		} else if len(com) < 5 {
			return s.numericReply(c, 461, "Not enough parameters")
		}

		c.User = com[1]
		if com[2] != "0" || com[3] != "*" {
			// TODO: find appropriate error code
			return s.numericReply(c, 0, "Wrong protocol")
		}
		c.Realname = strings.Join(com[4:], " ")

		s.endRegistration(c)
	default:
		return s.numericReply(c, 421, fmt.Sprintf("Unknown command '%s'", com[0]))
	}

	return nil
}

// TODO: If we add capability negotiation, then that logic will have to go here as well
// when a client successfully calls USER/NICK, they are registered
func (s *Server) endRegistration(c *client.Client) {
	if c.Nick != "" && c.User != "" {
		c.Registered = true

		// send RPL_WELCOME and friends in acceptance
		c.Write(s.numericReply(c, 001, fmt.Sprintf("Welcome to the Internet Relay Network %s[!%s@%s]", c.Nick, c.User, c.Host.String())))
		c.Write(s.numericReply(c, 002, fmt.Sprintf("Your host is %s", s.Listener.Addr().String())))
		c.Write(s.numericReply(c, 003, fmt.Sprintf("This server was created %s", s.Created)))

		// TODO: send proper response messages
		c.Write(s.numericReply(c, 004, ""))
		c.Write(s.numericReply(c, 005, ""))

		// TODO: send LUSERS and MOTD
		log.Println("successfully registered client")
	}
}

func (s *Server) numericReply(c *client.Client, errCode int, errString string) error {
	return fmt.Errorf(":%s %d %s :%s\r\n", s.Listener.Addr().String(), errCode, c.Nick, errString)
}
