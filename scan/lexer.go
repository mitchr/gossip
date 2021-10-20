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
	position int
	state    State

	current rune
	peeked  rune
	width   int
}

func (l *Lexer) Next() rune {
	// check peek cache
	if l.peeked != -1 {
		l.current = l.peeked
	} else {
		l.current = l.Peek()
	}
	l.peeked = -1

	l.position += l.width
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

	l.peeked, l.width = utf8.DecodeRune(l.input[l.position:])

	// input is garbled, force execution to end early
	if l.peeked == utf8.RuneError {
		l.position = len(l.input) // prevent subsequent calls to Peek/Next
		return rune(EOF)
	}

	return l.peeked
}

func (l *Lexer) Push(t TokenType) {
	l.tokens <- &Token{TokenType: t, Value: l.current}
}

// Lex generates a channel of tokens depending on the initial state
// given. This channel is closed whenever initState returns nil.
func Lex(b []byte, initState State) <-chan *Token {
	l := &Lexer{
		state:  initState,
		input:  b,
		tokens: make(chan *Token),
		peeked: -1,
	}

	go func() {
		for l.state != nil {
			l.state = l.state(l)
		}
		close(l.tokens)
	}()

	return l.tokens
}
