// lexer based on Rob Pike's ivy bignum calculator
// https://github.com/robpike/ivy
// https://www.youtube.com/watch?v=PXoG0WX0r_E

package scan

import (
	"unicode/utf8"
)

type TokenType int8

const EOF rune = -1

var EOFToken Token = Token{TokenType(EOF), EOF, 0}

type Token struct {
	TokenType TokenType
	Value     rune
	width     uint8
}

func (t Token) String() string { return string(t.Value) }

type Lexer struct {
	tokens   TokQueue
	input    []byte
	position int

	current rune
	peeked  rune
	width   uint8
}

func (l *Lexer) Next() rune {
	// check peek cache
	if l.peeked != -1 {
		l.current = l.peeked
	} else {
		l.current = l.Peek()
	}
	l.peeked = -1

	l.position += int(l.width)
	return l.current
}

func (l *Lexer) Peek() rune {
	if l.position >= len(l.input) {
		return EOF
	}

	// check peek cache
	if l.peeked != -1 {
		return l.peeked
	}

	p, w := utf8.DecodeRune(l.input[l.position:])
	l.peeked, l.width = p, uint8(w)

	// input is garbled, force execution to end early
	if l.peeked == utf8.RuneError {
		l.position = len(l.input) // prevent subsequent calls to Peek/Next
	}

	return l.peeked
}

func (l *Lexer) Push(t TokenType) {
	l.tokens.push(Token{TokenType: t, Value: l.current, width: l.width})
}

// Lex creates a slice of tokens using the given initial state. Even if
// the returned error is not nil, some data may still be returned in the
// TokQueue. This is to ensure that proper error messages can be
// constructed from the invalid data.
func Lex(b []byte, initState func(*Lexer) error) (*TokQueue, error) {
	l := &Lexer{
		input:  b,
		peeked: -1,

		tokens: New(len(b)),
	}

	return &l.tokens, initState(l)
}
