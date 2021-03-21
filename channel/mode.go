package channel

import (
	"math"
	"strconv"
)

type prefix rune

const (
	// member
	Founder   prefix = '~'
	Protected prefix = '&'
	Operator  prefix = '@'
	Halfop    prefix = '%'
	Voice     prefix = '+'
)

var memberLetter = map[rune]prefix{
	'q': Founder,
	'a': Protected,
	'o': Operator,
	'h': Halfop,
	'v': Voice,
}

// a modeFunc modifies a channel's mode. It takes a channel to be
// modified, a parameter string, and a boolean. If true, perform
// actions to add the given mode to the channel. If false, remove the
// mode.
type modeFunc func(*Channel, string, bool)

var channelLetter = map[rune]struct {
	apply modeFunc
	// addConsumes is true if '+modeChar' takes a parameter, same for
	// remConsumes just '-modeChar'
	addConsumes, remConsumes bool
}{
	'b': {ban, true, true},
	'e': {banExcept, true, true},
	'l': {limit, true, false},
	'i': {invite, false, false},
	'I': {inviteExcept, true, true},
	'k': {key, true, false},
	'm': {moderated, false, false},
	's': {secret, false, false},
	't': {protected, false, false},
	'n': {noExternal, false, false},
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
		ch.Limit = math.MaxUint32
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
