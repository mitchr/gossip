package msg

import (
	"errors"
	"unicode/utf8"

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

func Lex(b []byte) ([]scan.Token, error) { return scan.Lex(b, lexMessage) }

func lexMessage(l *scan.Lexer) error {
	for {
		switch l.Next() {
		case utf8.RuneError:
			return errors.New("Messages must be encoded using UTF-8")
		case scan.EOF:
			return nil
		case '\r':
			l.Push(cr)
		case '\n':
			l.Push(lf)
		case ' ':
			// consume all space
			for l.Peek() == ' ' {
				l.Next()
			}
			l.Push(space)
		case ':':
			l.Push(colon)
		case '@':
			l.Push(at)
		case '!':
			l.Push(exclam)
		case ';':
			l.Push(semicolon)
		case '=':
			l.Push(equals)
		case '/':
			l.Push(fwdSlash)
		case '+':
			l.Push(clientPrefix)
		default:
			l.Push(any)
		}
	}
}
