package wild

import (
	"github.com/mitchr/gossip/scan"
)

const (
	wildone scan.TokenType = iota
	wildmany
	esc
	nowildesc
)

func lexWild(l *scan.Lexer) {
	for {
		switch l.Next() {
		case scan.EOF:
			return
		case '?':
			l.Push(wildone)
		case '*':
			l.Push(wildmany)
		case '\\':
			l.Push(esc)
		default:
			l.Push(nowildesc)
		}
	}
}

func Match(regex, m string) bool {
	p := &scan.Parser{Tokens: scan.Lex([]byte(regex), lexWild)}

	// position that we are currently matching on in m
	pos := 0

	for {
		switch r := p.Next(); {
		case r == nil:
			// if we were able to reach the end of the string without error, then it's a match
			return true
		case r.TokenType == nowildesc:
			if r.Value != getRune(m, pos) {
				return false
			}
			pos++
		case r.TokenType == esc:
			// if the next character is a '*' or '?', then disregard this '\'
			// and compare m against the appropriate wildcard
			if n := p.Peek(); n.TokenType == wildone || n.TokenType == wildmany {
				if n.Value != getRune(m, pos) {
					return false
				}
			} else {
				if r.Value != getRune(m, pos) {
					return false
				}
				pos++ // advance pointer
			}
		case r.TokenType == wildone:
			pos++
			// n := p.Next()
			// if n.Value != string(getRune(m, pos)) {
			// 	return false
			// }
		case r.TokenType == wildmany:
			stop := p.Peek()
			n := getRune(m, pos)
			for stop != nil && n != scan.EOF && n != stop.Value {
				pos++
				n = getRune(m, pos)
			}
		}
	}
}

func getRune(m string, i int) rune {
	if i > len(m)-1 {
		return scan.EOF
	} else {
		return rune(m[i])
	}
}
