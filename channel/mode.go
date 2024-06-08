package channel

import (
	"math"
	"strconv"
)

type prefix uint8

const (
	// member
	Founder prefix = 1 << iota
	Protected
	Operator
	Halfop
	Voice
)

func (p prefix) String() string {
	switch p {
	case Founder:
		return "~"
	case Protected:
		return "&"
	case Operator:
		return "@"
	case Halfop:
		return "%"
	case Voice:
		return "+"
	}

	var s string
	for i := Founder; i <= Voice; i <<= 1 {
		if p&i != 0 {
			s += i.String()
		}
	}
	return s
}

func (p prefix) modeLetters() string {
	switch p {
	case Founder:
		return "q"
	case Protected:
		return "a"
	case Operator:
		return "o"
	case Halfop:
		return "h"
	case Voice:
		return "v"
	}

	var s string
	for i := Founder; i <= Voice; i <<= 1 {
		if p&i != 0 {
			s += i.modeLetters()
		}
	}
	return s
}

var memberLetter = map[byte]prefix{
	'q': Founder,
	'a': Protected,
	'o': Operator,
	'h': Halfop,
	'v': Voice,
}

var MemberPrefix = map[byte]prefix{
	'~': Founder,
	'&': Protected,
	'@': Operator,
	'%': Halfop,
	'+': Voice,
}

// a modeFunc modifies a channel's mode. It takes a channel to be
// modified, a parameter string, and a boolean. If true, perform
// actions to add the given mode to the channel. If false, remove the
// mode.
type modeFunc func(*Channel, string, bool)

var channelLetter = map[byte]struct {
	apply modeFunc
	// addConsumes is true if '+modeChar' takes a parameter, same for
	// remConsumes just '-modeChar'
	addConsumes, remConsumes bool
	canList                  bool
}{
	'b': {ban, true, true, true},
	'e': {banExcept, true, true, true},
	'l': {limit, true, false, false},
	'i': {invite, false, false, false},
	'I': {inviteExcept, true, true, true},
	'k': {key, true, false, false},
	'm': {moderated, false, false, false},
	's': {secret, false, false, false},
	't': {protected, false, false, false},
	'n': {noExternal, false, false, false},
}

func ban(ch *Channel, mask string, add bool) {
	if add {
		ch.Ban = append(ch.Ban, mask)
	} else {
		for i := range ch.Ban {
			if ch.Ban[i] == mask {
				ch.Ban = append(ch.Ban[:i], ch.Ban[i+1:]...)
				return
			}
		}
	}
}

func banExcept(ch *Channel, mask string, add bool) {
	if add {
		ch.BanExcept = append(ch.BanExcept, mask)
	} else {
		for i := range ch.BanExcept {
			if ch.BanExcept[i] == mask {
				ch.BanExcept = append(ch.BanExcept[:i], ch.BanExcept[i+1:]...)
				return
			}
		}
	}
}

func limit(ch *Channel, param string, add bool) {
	if add {
		ch.Limit, _ = strconv.Atoi(param)
	} else {
		ch.Limit = math.MaxInt
	}
}

func invite(ch *Channel, p string, add bool) { ch.Invite = add }

func inviteExcept(ch *Channel, mask string, add bool) {
	if add {
		ch.InviteExcept = append(ch.InviteExcept, mask)
	} else {
		for i := range ch.InviteExcept {
			if ch.InviteExcept[i] == mask {
				ch.InviteExcept = append(ch.InviteExcept[:i], ch.InviteExcept[i+1:]...)
				return
			}
		}
	}
}

func key(ch *Channel, param string, add bool) {
	if add {
		ch.Key = param
	} else {
		ch.Key = ""
	}
}

func moderated(ch *Channel, p string, add bool)  { ch.Moderated = add }
func secret(ch *Channel, p string, add bool)     { ch.Secret = add }
func protected(ch *Channel, p string, add bool)  { ch.Protected = add }
func noExternal(ch *Channel, p string, add bool) { ch.NoExternal = add }
