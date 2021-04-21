package msg

import (
	"log"

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
		p.Next() // consume '@'
		m.tags = tags(p)
		if !p.Expect(space) {
			log.Println("expected space")
			return nil
		}
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

// <tag> *[';' <tag>]
func tags(p *scan.Parser) map[string]TagVal {
	t := make(map[string]TagVal)

	// expect atleast 1 tag
	k, v := tag(p)
	t[k] = v

	for {
		if p.Peek().TokenType == semicolon {
			p.Next() // consume ';'
			k, v := tag(p)
			t[k] = v
		} else {
			break
		}
	}

	return t
}

// [ <client_prefix> ] <key> ['=' <escaped_value>]
func tag(p *scan.Parser) (k string, val TagVal) {
	if p.Peek().TokenType == clientPrefix {
		val.ClientPrefix = true
		p.Next() // consume '+'
	}

	// TODO parse vendor (this is nontrivial I think)

	val.Vendor, k = key(p)

	if p.Peek().TokenType == equals {
		p.Next() // consume '='
		val.Value = escapedVal(p)
	}

	return
}

// [ <vendor> '/' ] <key_name>
func key(p *scan.Parser) (vendor, key string) {
	// we can't know that we were given a vendor until we see '/', so we
	// consume generically to start and don't make any assumptions
	name := ""
	unusedDot := false
	for {
		k := p.Peek()
		r := rune(p.Peek().Value[0])

		if !isKeyname(r) {
			if k.Value[0] == '.' { // found a DNS name
				unusedDot = true
			} else if k.TokenType == fwdSlash { // vendor token is finished
				unusedDot = false
				vendor = name
				name = ""
				p.Next() // skip '/'
				continue
			} else if unusedDot { // found a dot in the keyName, which is not allowed
				log.Println("ill-formed key", vendor, key)
				return "", ""
			} else {
				key = name
				return
			}
		}
		name += k.Value
		p.Next()
	}
}

// <sequence of zero or more utf8 characters except NUL, CR, LF, semicolon (`;`) and SPACE>
func escapedVal(p *scan.Parser) string {
	val := ""
	for {
		v := p.Peek()
		if r := rune(v.Value[0]); !isEscaped(r) {
			break
		}
		val += v.Value
		p.Next()
	}
	return val
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
		if n.TokenType == space || n.TokenType == exclam || n.TokenType == at {
			break
		}

		nick += n.Value
		p.Next()
	}
	// get user
	if p.Peek().TokenType == exclam {
		p.Next() // consume '!'
		for {
			u := p.Peek()
			if u.TokenType == space || u.TokenType == at {
				break
			}

			user += u.Value
			p.Next()
		}
	}
	// get host
	if p.Peek().TokenType == at {
		p.Next() // consume '@'
		for {
			h := p.Peek()
			if h.TokenType == space {
				break
			}

			host += h.Value
			p.Next()
		}
	}

	return nick, user, host
}

// 1*letter / 3digit
func command(p *scan.Parser) string {
	c := ""
	for scan.IsLetter(rune(p.Peek().Value[0])) {
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
			p.Next()
		} else if isNospcrlfcl(t.Value[0]) {
			m += nospcrlfcl(p)
		} else {
			break
		}
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

// <non-empty sequence of ascii letters, digits, hyphens ('-')>
func isKeyname(r rune) bool {
	return scan.IsLetter(r) || scan.IsDigit(r) || r == '-'
}

func isEscaped(r rune) bool {
	return r != 0 && r != '\r' && r != '\n' && r != ';' && r != ' '
}
