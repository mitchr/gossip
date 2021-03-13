package scan

type Parser struct {
	Tokens []Token
	start  int
	pos    int
}

func (p *Parser) Next() Token {
	if p.pos == len(p.Tokens) {
		return Token{EOF, ""} // nil token
	}
	t := p.Tokens[p.pos]
	p.pos++
	return t
}

func (p *Parser) Peek() Token {
	if p.pos == len(p.Tokens) {
		return Token{EOF, ""} // nil token
	}
	t := p.Next()
	p.pos--
	return t
}

func (p *Parser) Expect(t TokenType) bool {
	return p.Next().TokenType == t
}
