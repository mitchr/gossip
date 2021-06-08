// lexer based on Rob Pike's ivy bignum calculator
// https://github.com/robpike/ivy
// https://www.youtube.com/watch?v=PXoG0WX0r_E

package scan

import (
	"unicode/utf8"
)

type TokenType int

const (
	EOF = -1
)

// A Token is also a node for a queue
type Token struct {
	TokenType TokenType
	Value     rune

	next *Token
}

func (t Token) String() string { return string(t.Value) }

type State func(*Lexer) State

type Lexer struct {
	tokens   *queue
	input    []byte
	start    int
	position int
	state    State
}

func (l *Lexer) Next() rune {
	if l.position == len(l.input) {
		return rune(EOF)
	}

	r, width := utf8.DecodeRune(l.input[l.position:])
	// if r == utf8.RuneError {
	// TODO: should probably throw the entire tokenstream out since the
	// input is garbled
	// }
	l.position += width
	return r
}

func (l *Lexer) Peek() rune {
	if l.position == len(l.input) {
		return EOF
	}

	r, _ := utf8.DecodeRune(l.input[l.position:])
	return r
}

func (l *Lexer) Ignore() {
	l.start = l.position
}

func (l *Lexer) Push(t TokenType) {
	r, _ := utf8.DecodeRune(l.input[l.start:])
	l.tokens.offer(&Token{TokenType: t, Value: r})
	l.start = l.position
}

func Lex(b []byte, initState State) *queue {
	l := &Lexer{
		state:  initState,
		input:  b,
		tokens: &queue{},
	}

	for l.state != nil {
		l.state = l.state(l)
	}

	return l.tokens
}
