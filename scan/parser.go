package scan

type Parser struct {
	Tokens <-chan *Token

	peeked *Token
}

func (p *Parser) Next() *Token {
	if p.peeked != nil {
		temp := p.peeked
		p.peeked = nil
		return temp
	}

	return <-p.Tokens
}

// Multiple calls to Peek will continue to return the same value until
// Next is called.
func (p *Parser) Peek() *Token {
	if p.peeked != nil {
		return p.peeked
	}

	p.peeked = <-p.Tokens
	if p.peeked == nil {
		return &Token{TokenType(EOF), -1}
	}
	return p.peeked
}

func (p *Parser) Expect(t TokenType) bool {
	next := p.Next()
	if next == nil {
		return false
	}

	return next.TokenType == t
}

// a-zA-z
func IsLetter(r rune) bool { return (r >= 65 && r <= 90) || (r >= 97 && r <= 122) }
func IsDigit(r rune) bool  { return r >= 48 && r <= 57 }
