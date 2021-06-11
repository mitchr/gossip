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
}

func (t Token) String() string { return string(t.Value) }

type State func(*Lexer) State

type Lexer struct {
	tokens   chan *Token
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

func (l *Lexer) Push(t TokenType) {
	r, _ := utf8.DecodeRune(l.input[l.start:])
	l.tokens <- &Token{TokenType: t, Value: r}
	l.start = l.position
}

func Lex(b []byte, initState State) <-chan *Token {
	l := &Lexer{
		state:  initState,
		input:  b,
		tokens: make(chan *Token),
	}

	go func() {
		for l.state != nil {
			l.state = l.state(l)
		}
		close(l.tokens)
	}()

	return l.tokens
}
