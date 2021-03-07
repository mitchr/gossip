// lexer based on Rob Pike's ivy bignum calculator
// https://github.com/robpike/ivy
// https://www.youtube.com/watch?v=PXoG0WX0r_E

package msg

import (
	"log"
	"unicode"
)

type tokenType int

const (
	eof = -1

	// message parameter matching
	nospcrlfcl tokenType = iota
	at
	colon
	exclam
	space
	crlf

	// modeStr
	plus tokenType = iota
	minus
	modechar
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
		return rune(eof)
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

func lex(b []byte, initState state) []token {
	l := &lexer{
		state: initState,
		input: b,
	}

	for l.state != nil {
		l.state = l.state(l)
	}

	return l.tokens
}

func lexMessage(l *lexer) state {
	switch r := l.next(); {
	case r == eof:
		return nil
	case r == '\r':
		if l.peek() == '\n' {
			l.next()
			l.push(crlf)
		}
		return lexMessage
	case r == ' ':
		for l.peek() == ' ' {
			l.next()
		}
		l.push(space)
		return lexMessage
	case r == ':':
		l.push(colon)
		return lexMessage
	case r == '@':
		l.push(at)
		return lexMessage
	case r == '!':
		l.push(exclam)
		return lexMessage
	case isNospcrlfcl(r):
		for s := l.peek(); isNospcrlfcl(s) && s != eof; s = l.peek() {
			l.next()
		}
		l.push(nospcrlfcl)
		return lexMessage
	default:
		log.Println("Unrecognized character: ", r, string(r))
		return nil
	}
}

// mode lexing
func lexMode(l *lexer) state {
	switch r := l.next(); {
	case r == eof:
		return nil
	case r == '+':
		l.push(plus)
		return lexMode
	case r == '-':
		l.push(minus)
		return lexMode
	case unicode.IsLetter(r): // isLetter == a-zA-z?
		l.push(modechar)
		return lexMode
	default:
		return nil
	}
}

// is not space, cr, lf, or colon (or NULL)
func isNospcrlfcl(r rune) bool {
	// use <= 0 to account for NUL and eof at same time
	return r != 0 && r != '\r' && r != '\n' && r != ':' && r != ' '
}