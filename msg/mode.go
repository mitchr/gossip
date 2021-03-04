package msg

// modestring  =  1*( modeset )
func ParseMode(b []byte) (addSet []rune, subSet []rune) {
	p := &parser{tokens: lex(b, lexMode)}

	// must have atleast one modeset
	chars, op := p.modeset()
	if op == plus {
		addSet = append(addSet, chars...)
	} else {
		subSet = append(subSet, chars...)
	}
	for {
		if r := p.peek().tokenType; r == plus || r == minus {
			chars, op := p.modeset()
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
func (p *parser) modeset() ([]rune, tokenType) {
	set := []rune{}
	operator := p.next().tokenType
	for {
		if p.peek().tokenType == modechar {
			r := p.next()
			set = append(set, rune(r.value[0]))
		} else {
			break
		}
	}
	return set, operator
}
