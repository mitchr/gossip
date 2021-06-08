package mode

import (
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
	for r := l.Next(); r != scan.EOF; r = l.Next() {
		switch k := r; {
		case k == '+':
			l.Push(plus)
		case k == '-':
			l.Push(minus)
		case scan.IsLetter(k):
			l.Push(modechar)
		}
	}
	return nil
}

type Mode struct {
	ModeChar rune
	Add      bool
	// accepts a param if nonempty (used for channel modes)
	Param string
}

// modestring  =  1*( modeset )
func Parse(b []byte) []Mode {
	p := &scan.Parser{Tokens: scan.Lex(b, lexMode)}
	m := []Mode{}

	// must have atleast one modeset
	chars, op := modeset(p)
	for _, v := range chars {
		m = append(m, Mode{ModeChar: v, Add: op == plus})
	}
	for {
		if r := p.Peek().TokenType; r == plus || r == minus {
			chars, op := modeset(p)
			for _, v := range chars {
				m = append(m, Mode{ModeChar: v, Add: op == plus})
			}
		} else {
			return m
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
			set = append(set, r.Value)
		} else {
			break
		}
	}
	return set, operator
}
