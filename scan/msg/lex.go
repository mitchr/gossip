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

func lexMessage(l *scan.Lexer) scan.State {
	switch r := l.Next(); {
	case r == scan.EOF:
		return nil
	case r == '\r':
		l.Push(cr)
		return lexMessage
	case r == '\n':
		l.Push(lf)
		return lexMessage
	case r == ' ': // consome all space
		for l.Peek() == ' ' {
			l.Next()
		}
		l.Push(space)
		return lexMessage
	case r == ':':
		l.Push(colon)
		return lexMessage
	case r == '@':
		l.Push(at)
		return lexMessage
	case r == '!':
		l.Push(exclam)
		return lexMessage
	case r == ';':
		l.Push(semicolon)
		return lexMessage
	case r == '=':
		l.Push(equals)
		return lexMessage
	case r == '/':
		l.Push(fwdSlash)
		return lexMessage
	case r == '+':
		l.Push(clientPrefix)
		return lexMessage
	default:
		l.Push(any)
		return lexMessage
	}
}
