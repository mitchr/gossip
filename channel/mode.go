package channel

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
	// 'b': Ban,
	// 'e': Exception,
	// 'l': ChanLimit,
	// 'i': InviteOnly,
	// 'I': InviteException,
	'k': {key, true, false},
	// 'm': Moderated,
	// 's': Secret,
	// 't': protected,
	// 'n': NoExternalMsgs,
}

func key(ch *Channel, param string, add bool) {
	if add {
		ch.Key = param
	} else {
		ch.Key = ""
	}
}
