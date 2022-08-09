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
func lexMode(l *scan.Lexer) error {
	for {
		switch k := l.Next(); {
		case k == scan.EOF:
			return nil
		case k == '+':
			l.Push(plus)
		case k == '-':
			l.Push(minus)
		case scan.IsLetter(k):
			l.Push(modechar)
		}
	}
}

type Type int

const (
	Add Type = iota
	Remove
	List
)

type Mode struct {
	ModeChar rune
	Type     Type
	// accepts a param if nonempty (used for channel modes)
	Param string
}

func (m Mode) String() string {
	var s string
	if m.Type == Add {
		s += "+"
	} else if m.Type == Remove {
		s += "-"
	}
	return s + string(m.ModeChar)
}

// modestring  =  1*( modeset )
func Parse(b []byte) []Mode {
	tokens, _ := scan.Lex(b, lexMode)
	p := &scan.Parser{Tokens: tokens}
	m := []Mode{}

	// must have atleast one modeset
	chars, op := modeset(p)
	for _, v := range chars {
		m = append(m, Mode{ModeChar: v, Type: op})
	}
	for {
		r := p.Peek()
		if r == scan.EOFToken || (r.TokenType != plus && r.TokenType != minus) {
			return m
		} else {
			chars, op := modeset(p)
			for _, v := range chars {
				m = append(m, Mode{ModeChar: v, Type: op})
			}
		}
	}
}

// some clients ask for mode listings with 'mode #chan b', so the abnf
// here is different than the spec
// modeset = plus / minus / modechar *(modechar)
func modeset(p *scan.Parser) ([]rune, Type) {
	set := []rune{}
	verb := p.Next()
	if verb.TokenType == modechar {
		set = append(set, verb.Value)
	}

	for {
		t := p.Peek()
		if t == scan.EOFToken || t.TokenType != modechar {
			break
		} else {
			r := p.Next()
			set = append(set, r.Value)
		}
	}
	return set, toType(verb.TokenType)
}

// maps a lexeme to the appropriate mode verb
func toType(s scan.TokenType) Type {
	if s == plus {
		return Add
	} else if s == minus {
		return Remove
	} else if s == modechar {
		return List
	}
	return -1
}
