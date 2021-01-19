// lexer based on Rob Pike's ivy bignum calculator
// https://github.com/robpike/ivy
// https://www.youtube.com/watch?v=PXoG0WX0r_E

package server

import (
	"log"
)

type tokenType int

const (
	// tokens used in parameter matching
	nospcrlfcl tokenType = iota
	at
	colon
	exclam

	space
	crlf
	eof = -1
)

type token struct {
	tokenType tokenType
	value     string
}

type state func(*lexer) state

type lexer struct {
	tokens   []token
	input    []byte
	start    int
	position int
	state    state
}

func (l *lexer) next() rune {
	if l.position == len(l.input) {
		return eof
	}

	r := rune(l.input[l.position])
	l.position++
	return r
}

func (l *lexer) peek() rune {
	if l.position == len(l.input) {
		return eof
	}

	r := l.next()
	l.position--
	return r
}

func (l *lexer) ignore() {
	l.start = l.position
}

func (l *lexer) push(t tokenType) {
	l.tokens = append(l.tokens, token{t, string(l.input[l.start:l.position])})
	l.start = l.position
}

func lex(b []byte) []token {
	l := &lexer{
		state: lexAny,
		input: b,
	}

	for l.state != nil {
		l.state = l.state(l)
	}

	return l.tokens
}

func lexAny(l *lexer) state {
	switch r := l.next(); {
	case r == eof:
		return nil
	case r == '\r':
		if l.next() == '\n' {
			l.push(crlf)
		}
		return lexAny
	case r == ' ':
		for l.peek() == ' ' {
			l.next()
		}
		l.push(space)
		return lexAny
	case r == ':':
		l.push(colon)
		return lexAny
	case r == '@':
		l.push(at)
		return lexAny
	case r == '!':
		l.push(exclam)
		return lexAny
	case isNospcrlfcl(r):
		for s := l.peek(); isNospcrlfcl(s) && s != eof; s = l.peek() {
			l.next()
		}
		l.push(nospcrlfcl)
		return lexAny
	default:
		log.Fatalf("Unrecognized character %v\n", string(r))
		return nil
	}
}

// is not space, cr, lf, or colon (or NULL)
func isNospcrlfcl(r rune) bool {
	// use <= 0 to account for NUL and eof at same time
	return !(r == 0 || r == '\r' || r == '\n' || r == ':' || r == ' ')
}
