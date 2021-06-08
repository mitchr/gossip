package scan

type Parser struct {
	Tokens *queue
}

var nilToken *Token = &Token{TokenType: EOF, Value: -1}

func (p *Parser) Next() *Token {
	t := p.Tokens.poll()
	if t == nil {
		return nilToken
	}
	return t
}

func (p *Parser) Peek() *Token {
	t := p.Tokens.peek()
	if t == nil {
		return nilToken
	}
	return t
}

func (p *Parser) Expect(t TokenType) bool {
	return p.Next().TokenType == t
}

// a-zA-z
func IsLetter(r rune) bool { return (r >= 65 && r <= 90) || (r >= 97 && r <= 122) }
func IsDigit(r rune) bool  { return r >= 48 && r <= 57 }
