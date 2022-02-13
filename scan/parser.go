package scan

type Parser struct {
	position int
	Tokens   []Token
}

func (p *Parser) Next() Token {
	t := p.Peek()
	p.position++
	return t
}

// Multiple calls to Peek will continue to return the same value until
// Next is called.
func (p *Parser) Peek() Token {
	if p.position > len(p.Tokens)-1 {
		return EOFToken
	}
	return p.Tokens[p.position]
}

func (p *Parser) Expect(t TokenType) bool {
	next := p.Next()
	if next == EOFToken {
		return false
	}

	return next.TokenType == t
}

// a-zA-z
func IsLetter(r rune) bool { return (r >= 65 && r <= 90) || (r >= 97 && r <= 122) }
func IsDigit(r rune) bool  { return r >= 48 && r <= 57 }
