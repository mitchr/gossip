package msg

import (
	"github.com/mitchr/gossip/scan"
)

const (
	any scan.TokenType = iota
	at
	colon
	exclam
	space
	cr
	lf

	// tags
	semicolon
	equals
	fwdSlash
	clientPrefix
)

func LexMessage(r rune) scan.Token {
	switch r {
	case '\r':
		return scan.Token{TokenType: cr, Value: r}
	case '\n':
		return scan.Token{TokenType: lf, Value: r}
	case ' ':
		return scan.Token{TokenType: space, Value: r}
	case ':':
		return scan.Token{TokenType: colon, Value: r}
	case '@':
		return scan.Token{TokenType: at, Value: r}
	case '!':
		return scan.Token{TokenType: exclam, Value: r}
	case ';':
		return scan.Token{TokenType: semicolon, Value: r}
	case '=':
		return scan.Token{TokenType: equals, Value: r}
	case '/':
		return scan.Token{TokenType: fwdSlash, Value: r}
	case '+':
		return scan.Token{TokenType: clientPrefix, Value: r}
	default:
		return scan.Token{TokenType: any, Value: r}
	}
}
