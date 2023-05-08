package msg

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mitchr/gossip/scan"
)

const (
	maxTags = 4096
	maxMsg  = 512
)

var (
	ErrMsgSizeOverflow = errors.New("message too large")
	ErrParse           = errors.New("parse error")
)

// given a slice of tokens, produce a corresponding irc message
// ["@" tags SPACE] [":" source SPACE] command [params] crlf
// If a parsing error occurs, Parse will return a Message with as much
// of the tokens from t processed.
func Parse(t *scan.TokQueue) (*Message, error) {
	if t.Peek() == scan.EOFToken {
		return nil, fmt.Errorf("%v: empty message", ErrParse)
	}

	p := &scan.Parser{Tokens: t}
	m := &Message{}

	if p.Peek().TokenType == at {
		p.Next() // consume '@'
		m.tags = tags(p)
		if !p.Expect(space) {
			return nil, fmt.Errorf("%w: expected space", ErrParse)
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
			return nil, fmt.Errorf("%w: expected space", ErrParse)
		}
	}
	m.Command = command(p)
	m.Params, m.trailingSet = params(p)

	// expect a crlf ending
	if !p.Expect(cr) {
		return m, fmt.Errorf("%w: no cr; ignoring", ErrParse)
	}
	if !p.Expect(lf) {
		return m, fmt.Errorf("%w: no lf; ignoring", ErrParse)
	}

	return m, nil
}

// <tag> *[';' <tag>]
func tags(p *scan.Parser) []Tag {
	t := []Tag{}

	// expect atleast 1 tag
	c, k, v := tag(p)
	t = append(t, Tag{c, k, v})

	for p.Peek().TokenType == semicolon {
		p.Next() // consume ';'
		c, k, v = tag(p)
		t = append(t, Tag{c, k, v})
	}
	return t
}

// [ <client_prefix> ] <key> ['=' <escaped_value>]
func tag(p *scan.Parser) (clientTag bool, k string, val string) {
	if p.Peek().TokenType == clientPrefix {
		clientTag = true
		p.Next() // consume '+'
	}

	k = key(p)

	if p.Peek().TokenType == equals {
		p.Next() // consume '='
		val = escapedVal(p)
	}

	return
}

// [ <vendor> '/' ] <key_name>
func key(p *scan.Parser) string {
	k := vendor(p)
	if p.Peek().TokenType == fwdSlash {
		k += string(p.Next().Value)
		k += keyName(p)
	}
	return k
}

// https://www.rfc-editor.org/rfc/rfc952
// <hname> ::= <name>*["."<name>]
// <name>  ::= <let>[*[<let-or-digit-or-hyphen>]<let-or-digit>]
func vendor(p *scan.Parser) string {
	var v string
	for isKeyname(p.Peek().Value) {
		v += string(p.Next().Value)
	}
	if p.Peek().Value == '.' {
		v += string(p.Next().Value)
		v += vendor(p)
	}
	return v
}

func keyName(p *scan.Parser) string {
	var k string
	for isKeyname(p.Peek().Value) {
		k += string(p.Next().Value)
	}
	return k
}

// <sequence of zero or more utf8 characters except NUL, CR, LF, semicolon (`;`) and SPACE>
func escapedVal(p *scan.Parser) string {
	var val string
	for isEscaped(p.Peek().Value) {
		val += string(p.Next().Value)
	}
	return val
}

// nickname [ [ "!" user ] "@" host ]
func source(p *scan.Parser) (string, string, string) {
	var b strings.Builder
	var nick, user, host string

	// get nickname
	for n := p.Peek().TokenType; n != space && n != exclam && n != at; n = p.Peek().TokenType {
		b.WriteRune(p.Next().Value)
	}
	nick = b.String()
	b.Reset()

	// get user
	if p.Peek().TokenType == exclam {
		p.Next() // consume '!'
		for u := p.Peek().TokenType; u != space && u != at; u = p.Peek().TokenType {
			b.WriteRune(p.Next().Value)
		}
		user = b.String()
		b.Reset()
	}

	// get host
	if p.Peek().TokenType == at {
		p.Next() // consume '@'
		for p.Peek().TokenType != space {
			b.WriteRune(p.Next().Value)
		}
		host = b.String()
	}

	return nick, user, host
}

// 1*letter / 3digit
func command(p *scan.Parser) string {
	var c strings.Builder
	for scan.IsLetter(p.Peek().Value) {
		c.WriteRune(p.Next().Value)
	}
	return c.String()
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
	var m strings.Builder
	m.WriteString(nospcrlfcl(p))

	for {
		switch t := p.Peek(); {
		case t.TokenType == colon:
			m.WriteRune(t.Value)
			p.Next()
		case isNospcrlfcl(t.Value):
			m.WriteString(nospcrlfcl(p))
		default:
			return m.String()
		}
	}
}

// *( ":" / " " / nospcrlfcl )
func trailing(p *scan.Parser) string {
	var m strings.Builder
	for {
		switch t := p.Peek(); {
		case t.TokenType == colon, t.TokenType == space:
			m.WriteRune(t.Value)
			p.Next()
		case isNospcrlfcl(t.Value):
			m.WriteString(nospcrlfcl(p))
		default:
			return m.String()
		}
	}
}

// <sequence of any characters except NUL, CR, LF, colon (`:`) and SPACE>
func nospcrlfcl(p *scan.Parser) string {
	var tok strings.Builder
	for isNospcrlfcl(p.Peek().Value) {
		tok.WriteRune(p.Next().Value)
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
