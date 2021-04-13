// lexer based on Rob Pike's ivy bignum calculator
// https://github.com/robpike/ivy
// https://www.youtube.com/watch?v=PXoG0WX0r_E

package scan

import "unicode/utf8"

type TokenType int

const (
	EOF = -1
)

type Token struct {
	TokenType TokenType
	Value     string
}

type State func(*Lexer) State

type Lexer struct {
	tokens   []Token
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
	l.tokens = append(l.tokens, Token{t, string(l.input[l.start:l.position])})
	l.start = l.position
}

func Lex(b []byte, initState State) []Token {
	l := &Lexer{
		state: initState,
		input: b,
	}

	for l.state != nil {
		l.state = l.state(l)
	}

	return l.tokens
}
