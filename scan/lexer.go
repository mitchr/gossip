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
	width     int
}

func (t Token) String() string { return string(t.Value) }

type State func(*Lexer) error

type Lexer struct {
	tokens   []Token
	input    []byte
	position int

	current rune
	peeked  rune
	width   int
}

var ErrUtf8Only error = errors.New("Messages must be encoded using UTF-8")

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
		return EOF
	}

	return l.peeked
}

func (l *Lexer) Push(t TokenType) {
	l.tokens = append(l.tokens, Token{TokenType: t, Value: l.current, width: l.width})
}

// Lex creates a slice of tokens using the given initial state
func Lex(b []byte, initState State) ([]Token, error) {
	l := &Lexer{
		input:  b,
		peeked: -1,

		// allocate enough space to hold a token for every byte in the input
		tokens: make([]Token, 0, len(b)),
	}

	err := initState(l)
	if err != nil {
		return nil, err
	}

	return l.tokens, nil
}
