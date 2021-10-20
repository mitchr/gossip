package scan

import (
	"testing"
)

func TestNextError(t *testing.T) {
	input := "\xFF normal data"
	l := &Lexer{input: []byte(input), peeked: -1}

	eof := l.Next()
	if eof != EOF && l.position != len(l.input) {
		t.Errorf("could not throw out garbled input stream; got %s\n", string(eof))
	}

	// subsequent call to Next should return EOF
	if l.Next() != EOF {
		t.Error("continued to read from input stream after RuneError")
	}
}
