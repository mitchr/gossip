package scan

type Parser struct {
	Tokens    *TokQueue
	BytesRead uint16
}

func (p *Parser) Next() Token {
	t := p.Tokens.pop()
	p.BytesRead += uint16(t.width)
	return t
}

// Multiple calls to Peek will continue to return the same value until
// Next is called.
func (p *Parser) Peek() Token {
	return p.Tokens.Peek()
}

func (p *Parser) Expect(t TokenType) bool {
	return p.Next().TokenType == t
}

// a-zA-z
func IsLetter(r rune) bool { return (r >= 65 && r <= 90) || (r >= 97 && r <= 122) }
func IsDigit(r rune) bool  { return r >= 48 && r <= 57 }
