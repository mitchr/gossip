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
func lexMode(r rune) scan.Token {
	switch k := r; {
	case k == '+':
		return scan.Token{TokenType: plus, Value: r}
	case k == '-':
		return scan.Token{TokenType: minus, Value: r}
	case scan.IsLetter(k):
		return scan.Token{TokenType: modechar, Value: r}
	}
	return scan.EOFToken
}

type Type int

const (
	Add Type = iota
	Remove
	List
)

type Mode struct {
	ModeChar byte
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
	p := &scan.Parser{Lexer: scan.Lex(b, lexMode)}
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
func modeset(p *scan.Parser) ([]byte, Type) {
	set := []byte{}
	verb := p.Next()
	if verb.TokenType == modechar {
		set = append(set, byte(verb.Value))
	}

	for {
		t := p.Peek()
		if t == scan.EOFToken || t.TokenType != modechar {
			break
		} else {
			r := p.Next()
			set = append(set, byte(r.Value))
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
	}
	return List
}
