package mode

import (
	"unicode"

	"github.com/mitchr/gossip/scan"
)

const (
	// modeStr
	plus scan.TokenType = iota
	minus
	modechar
)

// mode lexing
func lexMode(l *scan.Lexer) scan.State {
	switch r := l.Next(); {
	case r == scan.EOF:
		return nil
	case r == '+':
		l.Push(plus)
		return lexMode
	case r == '-':
		l.Push(minus)
		return lexMode
	case unicode.IsLetter(r): // isLetter == a-zA-z?
		l.Push(modechar)
		return lexMode
	default:
		return nil
	}
}

// modestring  =  1*( modeset )
func Parse(b []byte) (addSet []rune, subSet []rune) {
	p := &scan.Parser{Tokens: scan.Lex(b, lexMode)}

	// must have atleast one modeset
	chars, op := modeset(p)
	if op == plus {
		addSet = append(addSet, chars...)
	} else {
		subSet = append(subSet, chars...)
	}
	for {
		if r := p.Peek().TokenType; r == plus || r == minus {
			chars, op := modeset(p)
			if op == plus {
				addSet = append(addSet, chars...)
			} else {
				subSet = append(subSet, chars...)
			}
		} else {
			return addSet, subSet
		}
	}
}

// modeset = plusminus *( modechar )
func modeset(p *scan.Parser) ([]rune, scan.TokenType) {
	set := []rune{}
	operator := p.Next().TokenType
	for {
		if p.Peek().TokenType == modechar {
			r := p.Next()
			set = append(set, rune(r.Value[0]))
		} else {
			break
		}
	}
	return set, operator
}
