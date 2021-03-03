package message

import (
	"log"
	"strings"
)

type parser struct {
	tokens []token
	start  int
	pos    int
}

func (p *parser) next() token {
	if p.pos == len(p.tokens) {
		return token{eof, ""} // nil token
	}
	t := p.tokens[p.pos]
	p.pos++
	return t
}

func (p *parser) peek() token {
	if p.pos == len(p.tokens) {
		return token{eof, ""} // nil token
	}
	t := p.next()
	p.pos--
	return t
}

// TODO: whenever expect fails, then the entire message should fail
func (p *parser) expect(t tokenType) bool {
	return p.next().tokenType == t
}

// given a slice of tokens, produce a corresponding irc message
// uses recursive descent obv
func Parse(t []token) *Message {
	p := &parser{tokens: t}
	m := &Message{}

	if p.peek().tokenType == at {
		// TODO: p.tags()
	}
	if p.peek().tokenType == colon {
		p.next() // consume colon
		m.nick, m.user, m.host = p.source()
		if !p.expect(space) {
			log.Println("expected space")
			return nil
		}
	}
	m.Command = p.command(p.next())
	if p.peek().tokenType == space {
		m.middle, m.trailing = p.params()
	}
	if !p.expect(crlf) {
		log.Println("no crlf; ignoring")
		return nil
	}

	return m
}

// because of the way nospcrlfcl's are lexed, we are not able to
// differentiate between character strings with other special characters
// in them (like '!' or '@'), so we have to do this ugly slicing
// TODO: one way we could make this better is by imposing some kind of
// restriction on how nick/user/host names look, so we could then create
// a rule for the lexer that would allow them to be tokenized. as far as
// I can tell, the IRC spec leaves handling of nick/user/host name up to
// the server implementation, but I think restricting to ASCII is fair
func (p *parser) source() (nick, user, host string) {
	source := p.next().value
	sourceInfo := strings.Split(source, "!")

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

// either a valid IRC command, or a 3 digit numeric reply
func (p *parser) command(t token) string {
	return t.value
}

// *( SPACE middle ) [ SPACE ":" trailing ]
func (p *parser) params() (middle []string, trailing string) {
	for {
		// found end, so we are done
		if r := p.peek().tokenType; r == crlf || r == eof {
			return
		}

		// else, there is another parameter
		p.expect(space)
		r := p.next()
		if r.tokenType == colon {
			trailing = p.trailing()
		} else if r.tokenType == nospcrlfcl {
			middle = append(middle, p.middle(r))
		}
	}
}

// space already consumed, current token is nospcrlfcl
func (p *parser) middle(s token) string {
	m := s.value
	for t := p.peek(); t.tokenType == nospcrlfcl || t.tokenType == colon; t = p.peek() {
		m += t.value
		p.next()
	}
	return m
}

// *( ":" / " " / nospcrlfcl )
func (p *parser) trailing() string {
	m := ""
	for t := p.peek(); t.tokenType == colon || t.tokenType == space || t.tokenType == nospcrlfcl; t = p.peek() {
		m += t.value
		p.next()
	}
	return m
}
