package scan

type Parser struct {
	Tokens []Token
	pos    int
}

func (p *Parser) Next() Token {
	if p.pos == len(p.Tokens) {
		return Token{EOF, -1} // nil token
	}
	t := p.Tokens[p.pos]
	p.pos++
	return t
}

func (p *Parser) Peek() Token {
	if p.pos == len(p.Tokens) {
		return Token{EOF, -1} // nil token
	}
	t := p.Next()
	p.pos--
	return t
}

func (p *Parser) Expect(t TokenType) bool {
	return p.Next().TokenType == t
}

// a-zA-z
func IsLetter(r rune) bool { return (r >= 65 && r <= 90) || (r >= 97 && r <= 122) }
func IsDigit(r rune) bool  { return r >= 48 && r <= 57 }
