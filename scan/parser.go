package scan

type Parser struct {
	Tokens <-chan *Token

	peeked *Token
}

var nilToken *Token = &Token{TokenType: EOF, Value: -1}

func (p *Parser) Next() *Token {
	if p.peeked != nil {
		temp := p.peeked
		p.peeked = nil
		return temp
	}

	t := <-p.Tokens
	if t == nil {
		return nilToken
	}
	return t
}

// Multiple calls to Peek will continue to return the same value until
// Next is called.
func (p *Parser) Peek() *Token {
	if p.peeked != nil {
		return p.peeked
	}

	p.peeked = <-p.Tokens
	if p.peeked == nil {
		return nilToken
	}
	return p.peeked
}

func (p *Parser) Expect(t TokenType) bool {
	return p.Next().TokenType == t
}

// a-zA-z
func IsLetter(r rune) bool { return (r >= 65 && r <= 90) || (r >= 97 && r <= 122) }
func IsDigit(r rune) bool  { return r >= 48 && r <= 57 }
