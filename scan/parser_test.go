package scan

import "testing"

func TestPeekWithClosedChan(t *testing.T) {
	c := make(chan *Token)
	close(c)
	p := &Parser{Tokens: c}

	peeked := p.Peek()
	if peeked.TokenType != TokenType(EOF) || peeked.Value != -1 {
		t.Fail()
	}
}
