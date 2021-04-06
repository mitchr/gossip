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
	for r := l.Next(); r != scan.EOF; r = l.Next() {
		switch r {
		case '\r':
			l.Push(cr)
		case '\n':
			l.Push(lf)
		case ' ':
			return lexSpace(l)
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
	return nil
}

// consume all space ' '
func lexSpace(l *scan.Lexer) scan.State {
	for l.Peek() == ' ' {
		l.Next()
	}
	l.Push(space)
	return lexMessage
}
