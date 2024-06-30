// lexer based on Rob Pike's ivy bignum calculator
// https://github.com/robpike/ivy
// https://www.youtube.com/watch?v=PXoG0WX0r_E

package scan

import (
	"errors"
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
	TokenGenerator func(rune) Token

	input    []byte
	position int

	Peeked Token
}

func (l *Lexer) Reset(b []byte) {
	l.input = b
	l.position = 0
	l.Peeked = EOFToken
}

func (l *Lexer) Next() (rune, int) {
	if l.position >= len(l.input) {
		return EOF, 0
	}

	p, w := utf8.DecodeRune(l.input[l.position:])
	l.position += w

	// input is garbled, force execution to end early
	if p == utf8.RuneError {
		l.position = len(l.input) // prevent subsequent calls to Next
	}

	return p, w
}

func (l *Lexer) NextToken() (Token, error) {
	var err error
	var t Token

	// check peek cache
	if l.Peeked.TokenType != -1 {
		t = l.Peeked
	} else {
		t, err = l.PeekToken()
	}
	l.Peeked.TokenType = -1

	return t, err
}

func (l *Lexer) PeekToken() (Token, error) {
	// check peek cache
	if l.Peeked.TokenType != -1 {
		return l.Peeked, nil
	}

	r, w := l.Next()
	if r == utf8.RuneError {
		return EOFToken, errors.New("Messages must be encoded using UTF-8")
	} else if r == EOF {
		return EOFToken, nil
	}

	l.Peeked = l.TokenGenerator(r)
	l.Peeked.width = uint8(w)
	return l.Peeked, nil
}

// Lex returns a new Lexer with the given input and generator.
func Lex(b []byte, generator func(rune) Token) *Lexer {
	return &Lexer{
		input:          b,
		TokenGenerator: generator,
		Peeked:         EOFToken,
	}
}
