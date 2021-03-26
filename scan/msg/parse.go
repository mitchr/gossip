package msg

import (
	"log"
	"unicode"

	"github.com/mitchr/gossip/scan"
)

// given a slice of tokens, produce a corresponding irc message
//["@" tags SPACE] [":" source SPACE] command [params] crlf
func Parse(b []byte) *Message {
	if len(b) == 0 || b == nil {
		return nil
	}

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

	// expect a crlf ending
	if !p.Expect(cr) {
		log.Println("no cr; ignoring")
		return nil
	}
	if !p.Expect(lf) {
		log.Println("no lf; ignoring")
		return nil
	}

	return m
}

// TODO: one way we could make this better is by imposing some kind of
// restriction on how nick/user/host names look, so we could then create
// a rule for the lexer that would allow them to be tokenized. as far as
// I can tell, the IRC spec leaves handling of nick/user/host name up to
// the server implementation, but I think restricting to ASCII is fair
// nickname [ [ "!" user ] "@" host ]
func source(p *scan.Parser) (nick, user, host string) {
	// get nickname
	for {
		n := p.Peek()
		if n.TokenType != space && n.TokenType != exclam && n.TokenType != at {
			nick += n.Value
		} else {
			break
		}
		p.Next()
	}
	// get user
	if p.Peek().TokenType == exclam {
		p.Next() // consume '!'
		for {
			u := p.Peek()
			if u.TokenType != space && u.TokenType != at {
				user += u.Value
			} else {
				break
			}
			p.Next()
		}
	}
	// get host
	if p.Peek().TokenType == at {
		p.Next() // consume '@'
		for {
			h := p.Peek()
			if h.TokenType != space {
				host += h.Value
			} else {
				break
			}
			p.Next()
		}
	}

	return nick, user, host
}

// 1*letter / 3digit
func command(p *scan.Parser) string {
	c := ""
	for unicode.IsLetter(rune(p.Peek().Value[0])) {
		c += p.Next().Value
	}
	return c
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
	// should expect a first nospcrlfcl
	if !isNospcrlfcl(p.Peek().Value[0]) {
		return ""
	}
	m := nospcrlfcl(p)

	for {
		t := p.Peek()
		if t.TokenType == colon {
			m += t.Value
		} else if isNospcrlfcl(t.Value[0]) {
			m += nospcrlfcl(p)
		} else {
			break
		}
		p.Next()
	}
	return m
}

// *( ":" / " " / nospcrlfcl )
func trailing(p *scan.Parser) string {
	m := ""
	for {
		t := p.Peek()
		if t.TokenType == colon || t.TokenType == space {
			m += t.Value
			p.Next()
		} else if t.TokenType == scan.EOF {
			break
		} else if isNospcrlfcl(t.Value[0]) {
			m += nospcrlfcl(p)
		} else {
			break
		}
	}
	return m
}

// <sequence of any characters except NUL, CR, LF, colon (`:`) and SPACE>
func nospcrlfcl(p *scan.Parser) string {
	tok := ""
	for {
		s := p.Peek()
		if s.TokenType != scan.EOF && isNospcrlfcl(s.Value[0]) {
			tok += s.Value
			p.Next()
		} else {
			break
		}
	}
	return tok
}

// is not space, cr, lf, or colon (or NULL)
func isNospcrlfcl(b byte) bool {
	// use <= 0 to account for NUL and eof at same time
	return b != 0 && b != '\r' && b != '\n' && b != ':' && b != ' '
}
