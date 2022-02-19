package msg

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/mitchr/gossip/scan"
)

const (
	maxTags = 8191
	maxMsg  = 512
)

var (
	ErrMsgSizeOverflow = errors.New("message too large")
	ErrParse           = errors.New("parse error")
)

// given a slice of tokens, produce a corresponding irc message
//["@" tags SPACE] [":" source SPACE] command [params] crlf
func Parse(t []scan.Token) (*Message, error) {
	if len(t) == 0 {
		return nil, fmt.Errorf("%v: empty message", ErrParse)
	}

	p := &scan.Parser{Tokens: t}
	m := &Message{}

	if p.Peek().TokenType == at {
		p.Next() // consume '@'
		m.tags = tags(p)
		if !p.Expect(space) {
			return nil, fmt.Errorf("%v: expected space", ErrParse)
		}
	}
	tagBytes := p.BytesRead
	if tagBytes > maxTags {
		return nil, ErrMsgSizeOverflow
	}

	if p.Peek().TokenType == colon {
		p.Next() // consume colon
		m.Nick, m.User, m.Host = source(p)
		if !p.Expect(space) {
			return nil, fmt.Errorf("%v: expected space", ErrParse)
		}
	}
	m.Command = command(p)
	m.Params, m.trailingSet = params(p)

	// expect a crlf ending
	if !p.Expect(cr) {
		return nil, fmt.Errorf("%v: no cr; ignoring", ErrParse)
	}
	if !p.Expect(lf) {
		return nil, fmt.Errorf("%v: no lf; ignoring", ErrParse)
	}

	if p.BytesRead-tagBytes > maxMsg {
		return nil, ErrMsgSizeOverflow
	}

	return m, nil
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

		if !isKeyname(k.Value) {
			if k.Value == '.' { // found a DNS name
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
		name += string(k.Value)
		p.Next()
	}
}

// <sequence of zero or more utf8 characters except NUL, CR, LF, semicolon (`;`) and SPACE>
func escapedVal(p *scan.Parser) string {
	val := ""
	for {
		v := p.Peek()
		if !isEscaped(v.Value) {
			break
		}
		val += string(v.Value)
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

		nick += string(n.Value)
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

			user += string(u.Value)
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

			host += string(h.Value)
			p.Next()
		}
	}

	return nick, user, host
}

// 1*letter / 3digit
func command(p *scan.Parser) string {
	c := ""
	for scan.IsLetter(p.Peek().Value) {
		c += string(p.Next().Value)
	}
	return c
}

// *( SPACE middle ) [ SPACE ":" trailing ]
func params(p *scan.Parser) (m []string, trailingSet bool) {
	for {
		if p.Peek().TokenType == space {
			p.Next() // consume space
		} else {
			return
		}

		if p.Peek().TokenType == colon {
			p.Next() // consume ':'
			m = append(m, trailing(p))
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
	if !isNospcrlfcl(p.Peek().Value) {
		return ""
	}
	m := nospcrlfcl(p)

	for {
		t := p.Peek()
		if t.TokenType == colon {
			m += string(t.Value)
			p.Next()
		} else if isNospcrlfcl(t.Value) {
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
		if t == scan.EOFToken {
			break
		} else if t.TokenType == colon || t.TokenType == space {
			m += string(t.Value)
			p.Next()
		} else if isNospcrlfcl(t.Value) {
			m += nospcrlfcl(p)
		} else {
			break
		}
	}
	return m
}

// <sequence of any characters except NUL, CR, LF, colon (`:`) and SPACE>
func nospcrlfcl(p *scan.Parser) string {
	var tok strings.Builder
	for {
		s := p.Peek()
		if s != scan.EOFToken && isNospcrlfcl(s.Value) {
			tok.WriteRune(s.Value)
			p.Next()
		} else {
			break
		}
	}
	return tok.String()
}

// is not space, cr, lf, or colon (or NULL)
func isNospcrlfcl(r rune) bool {
	return r != 0 && r != '\r' && r != '\n' && r != ':' && r != ' '
}

// <non-empty sequence of ascii letters, digits, hyphens ('-')>
func isKeyname(r rune) bool {
	return scan.IsLetter(r) || scan.IsDigit(r) || r == '-'
}

func isEscaped(r rune) bool {
	return r != 0 && r != '\r' && r != '\n' && r != ';' && r != ' '
}
