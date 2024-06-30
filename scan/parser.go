package scan

type Parser struct {
	Lexer     *Lexer
	BytesRead uint16
	lexErr    error
}

func (p *Parser) Reset(b []byte) {
	p.Lexer.Reset(b)
	p.BytesRead = 0
	p.lexErr = nil
}

// if p encountered any utf8 errors when lexing, retrieve them here
func (p *Parser) CheckUTF8Error() error { return p.lexErr }

func (p *Parser) Next() Token {
	t, err := p.Lexer.NextToken()
	if err != nil {
		p.lexErr = err
	}
	p.BytesRead += uint16(t.width)
	return t
}

// Multiple calls to Peek will continue to return the same value until
// Next is called.
func (p *Parser) Peek() Token {
	t, err := p.Lexer.PeekToken()
	if err != nil {
		p.lexErr = err
	}
	return t
}

func (p *Parser) Expect(t TokenType) bool { return p.Next().TokenType == t }

// a-zA-z
func IsLetter(r rune) bool { return (r >= 65 && r <= 90) || (r >= 97 && r <= 122) }
func IsDigit(r rune) bool  { return r >= 48 && r <= 57 }
