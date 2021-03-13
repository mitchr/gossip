package msg

import (
	"log"
	"strings"

	"github.com/mitchr/gossip/scan"
)

// given a slice of tokens, produce a corresponding irc message
//["@" tags SPACE] [":" source SPACE] command [params] crlf
func Parse(b []byte) *Message {
	p := &scan.Parser{Tokens: scan.Lex(b, lexMessage)}
	m := &Message{}

	if p.Peek().TokenType == at {
		// TODO: p.tags()
	}
	if p.Peek().TokenType == colon {
		p.Next() // consume colon
		m.nick, m.user, m.host = source(p)
		if !p.Expect(space) {
			log.Println("expected space")
			return nil
		}
	}
	m.Command = command(p)
	m.middle, m.trailing, m.trailingSet = params(p)
	if !p.Expect(crlf) {
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
func source(p *scan.Parser) (nick, user, host string) {
	source := p.Next().Value
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
func command(p *scan.Parser) string {
	return p.Next().Value
}

// *( SPACE middle ) [ SPACE ":" trailing ]
func params(p *scan.Parser) (m []string, t string, trailingSet bool) {
	for {
		if p.Peek().TokenType == space {
			p.Next() // consume space
		} else {
			return
		}

		if p.Peek().TokenType == colon {
			p.Next() // consume ':'
			t = trailing(p)
			trailingSet = true
			return // trailing has to be at the end, so we're done
		} else {
			m = append(m, middle(p))
		}
	}
}

// nospcrlfcl *( ":" / nospcrlfcl )
func middle(p *scan.Parser) string {
	m := p.Peek().Value
	if !p.Expect(nospcrlfcl) {
		return ""
	}

	for t := p.Peek(); t.TokenType == nospcrlfcl || t.TokenType == colon; t = p.Peek() {
		m += t.Value
		p.Next()
	}
	return m
}

// *( ":" / " " / nospcrlfcl )
func trailing(p *scan.Parser) string {
	m := ""
	for t := p.Peek(); t.TokenType == colon || t.TokenType == space || t.TokenType == nospcrlfcl; t = p.Peek() {
		m += t.Value
		p.Next()
	}
	return m
}
