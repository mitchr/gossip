package scan

type Parser struct{ Tokens *Queue }

func (p *Parser) Next() Token { return p.Tokens.poll() }

// Multiple calls to Peek will continue to return the same value until
// Next is called.
func (p *Parser) Peek() Token { return p.Tokens.peek() }

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
