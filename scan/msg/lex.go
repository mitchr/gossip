package msg

import (
	"log"

	"github.com/mitchr/gossip/scan"
)

func lexMessage(l *scan.Lexer) scan.State {
	switch r := l.Next(); {
	case r == scan.EOF:
		return nil
	case r == '\r':
		if l.Peek() == '\n' {
			l.Next()
			l.Push(crlf)
		}
		return lexMessage
	case r == ' ':
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
	case isNospcrlfcl(r):
		for s := l.Peek(); isNospcrlfcl(s) && s != scan.EOF; s = l.Peek() {
			l.Next()
		}
		l.Push(nospcrlfcl)
		return lexMessage
	default:
		log.Println("Unrecognized character: ", r, string(r))
		return nil
	}
}

// is not space, cr, lf, or colon (or NULL)
func isNospcrlfcl(r rune) bool {
	// use <= 0 to account for NUL and eof at same time
	return r != 0 && r != '\r' && r != '\n' && r != ':' && r != ' '
}
