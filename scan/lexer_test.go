package scan

import (
	"testing"
	"unicode/utf8"
)

func TestNextError(t *testing.T) {
	input := "\xFF normal data"
	l := &Lexer{input: []byte(input)}

	nonRune, _ := l.Next()
	if nonRune != utf8.RuneError && l.position != len(l.input) {
		t.Errorf("could not throw out garbled input stream; got %s\n", string(nonRune))
	}

	// subsequent call to Next should return EOF
	if r, _ := l.Next(); r != EOF {
		t.Error("continued to read from input stream after RuneError")
	}
}
