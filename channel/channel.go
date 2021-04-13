package channel

import (
	"errors"
	"log"
	"math"
	"strconv"
	"strings"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/mode"
	"github.com/mitchr/gossip/scan/wild"
)

type ChanType rune

const (
	Remote ChanType = '#'
	Local  ChanType = '&'
)

type Channel struct {
	// Name is case-insensitive, stored internally in lower-case
	Name     string
	ChanType ChanType
	Topic    string

	// Modes string
	// array of nickmasks
	Ban          []string
	BanExcept    []string
	Limit        int
	Invite       bool
	InviteExcept []string
	Key          string
	Moderated    bool
	Secret       bool
	Protected    bool
	NoExternal   bool

	// Invited is a list of client nicks who have been INVITEd
	Invited []string

	// map of Nick to undelying client
	Members map[string]*Member
}

func New(name string, t ChanType) *Channel {
	return &Channel{
		Name:     name,
		ChanType: t,
		Limit:    math.MaxUint32,
		Members:  make(map[string]*Member),
	}
}

func (c Channel) String() string {
	return string(c.ChanType) + c.Name
}

func (c Channel) Modes() (modestr string, params []string) {
	if len(c.Ban) != 0 {
		modestr += "b"
		params = append(params, strings.Join(c.Ban, ","))
	}
	if len(c.BanExcept) != 0 {
		modestr += "e"
		params = append(params, strings.Join(c.BanExcept, ","))
	}
	if c.Limit != math.MaxUint32 {
		modestr += "l"
		params = append(params, strconv.Itoa(c.Limit))
	}
	if c.Invite {
		modestr += "i"
	}
	if len(c.InviteExcept) != 0 {
		params = append(params, strings.Join(c.InviteExcept, ","))
	}
	// don't share key in mode params
	if c.Key != "" {
		modestr += "k"
	}
	if c.Moderated {
		modestr += "m"
	}
	if c.Secret {
		modestr += "s"
	}
	if c.Protected {
		modestr += "t"
	}
	if c.NoExternal {
		modestr += "n"
	}
	return
}

// broadcast message to each client in channel
func (c *Channel) Write(b interface{}) (int, error) {
	var n int
	var errStrings []string

	for _, v := range c.Members {
		written, err := v.Write(b)
		if err != nil {
			errStrings = append(errStrings, err.Error())
			log.Println(err)
		}
		n += written
	}

	return n, errors.New(strings.Join(errStrings, "\n"))
}

var (
	KeyErr    = errors.New("ERR_BADCHANNELKEY")
	LimitErr  = errors.New("ERR_CHANNELISFULL")
	InviteErr = errors.New("ERR_INVITEONLYCHAN")
	BanErr    = errors.New("ERR_BANNEDFROMCHAN")
)

// Admit adds a client to this channel. A client c is admitted to enter
// a channel if:
//  1. If this channel has a key, the client supplies the correct key
//  2. admitting this client does not put the channel over the chanlimit
//	3. their nick has been given an INVITE
//	4. if they have not been given an INVITE, their nickmask is in the inviteException list
//  5. their nickmask is not included in the banlist
//  6. if they are in the banlist, they are in the except list
func (ch *Channel) Admit(c *client.Client, key string) error {
	if ch.Key != key {
		return KeyErr
	}
	if len(ch.Members) >= ch.Limit {
		return LimitErr
	}

	if ch.Invite {
		for _, v := range ch.InviteExcept {
			// client doesn't need an invite, add them
			if wild.Match(v, c.String()) {
				ch.Members[c.Nick] = &Member{Client: c}
				return nil
			}
		}
		for _, v := range ch.Invited {
			// client was invited
			if c.Nick == v {
				ch.Members[c.Nick] = &Member{Client: c}
				return nil
			}
		}
		return InviteErr
	}

	for _, v := range ch.Ban {
		if wild.Match(v, c.String()) { // nickmask found in banlist
			for _, k := range ch.BanExcept {
				if wild.Match(k, c.Nick) { // nickmask is an exception, so admit
					ch.Members[c.Nick] = &Member{Client: c}
					return nil
				}
			}
			return BanErr
		}
	}
	ch.Members[c.Nick] = &Member{Client: c}
	return nil
}

type NotInChanErr struct{ member string }

func (n NotInChanErr) Error() string { return n.member }

type UnknownModeErr struct{ char rune }

func (u UnknownModeErr) Error() string { return string(u.char) }

// ApplyMode applies the given modeStr to the channel. It does not
// verify that the sending client has the proper permissions to make
// those changes. It returns a string of all the modes that were
// successfully applied.
func (c *Channel) ApplyMode(b []byte, params []string) (string, error) {
	// keep track of which param we are currently looking at
	pos := 0
	applied := ""
	for _, m := range mode.Parse(b) {
		if p, ok := channelLetter[m.ModeChar]; ok {
			param := ""

			// this is an add mode and it takes a param, or it is a remove mode and it takes a param
			if (m.Add && p.addConsumes) || (!m.Add && p.remConsumes) {
				param = params[pos]
				pos++
			}

			p.apply(c, param, m.Add)
			if m.Add {
				applied += "+" + string(m.ModeChar)
			} else {
				applied += "-" + string(m.ModeChar)
			}
		} else if _, ok := memberLetter[m.ModeChar]; ok { // should apply this prefix to a member, not the channel
			member, belongs := c.Members[params[pos]]
			if !belongs {
				// give back given nick
				return applied, NotInChanErr{params[pos]}
			}

			member.ApplyMode(m)
			if m.Add {
				applied += "+" + string(m.ModeChar) + " " + params[pos]
			} else {
				applied += "-" + string(m.ModeChar) + " " + params[pos]
			}
			pos++
		} else {
			// give back error with the unknown mode char
			return applied, UnknownModeErr{m.ModeChar}
		}
	}
	return applied, nil
}
