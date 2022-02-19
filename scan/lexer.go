// lexer based on Rob Pike's ivy bignum calculator
// https://github.com/robpike/ivy
// https://www.youtube.com/watch?v=PXoG0WX0r_E

package scan

import "unicode/utf8"

type TokenType int8

const EOF rune = -1

var EOFToken Token = Token{TokenType(EOF), EOF, 0}

type Token struct {
	TokenType TokenType
	Value     rune
	width     int
}

func (t Token) String() string { return string(t.Value) }

type State func(*Lexer)

type Lexer struct {
	tokens   []Token
	tokenPos int

	input    []byte
	position int

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
		return EOF
	}

	return l.peeked
}

func (l *Lexer) Push(t TokenType) {
	l.tokens[l.tokenPos] = Token{TokenType: t, Value: l.current, width: l.width}
	l.tokenPos++
}

// Lex generates a channel of tokens depending on the initial state
// given. This channel is closed whenever initState returns nil.
func Lex(b []byte, initState State) []Token {
	// allocate enough space to hold a token for every byte in the input
	tokens := make([]Token, len(b))
	for i := range tokens {
		tokens[i] = EOFToken
	}

	l := &Lexer{
		input:  b,
		peeked: -1,
		tokens: tokens,
	}

	initState(l)

	return l.tokens
}
