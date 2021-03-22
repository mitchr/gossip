package channel

import (
	"errors"
	"log"
	"math"
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
	Name     string
	ChanType ChanType
	Topic    string

	Modes string
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

func (c *Channel) ApplyMode(b []byte, params []string) bool {
	m := mode.Parse(b)

	// keep track of which param we are currently looking at
	pos := 0

	for _, v := range m {
		if p, ok := channelLetter[v.ModeChar]; ok {
			param := ""

			if p.addConsumes || p.remConsumes {
				param = params[pos]
				pos++
			}

			if v.Add {
				c.Modes += string(v.ModeChar)
			} else {
				c.Modes = strings.Replace(c.Modes, string(v.ModeChar), "", -1)
			}
			p.apply(c, param, v.Add)
		} else if _, ok := memberLetter[v.ModeChar]; ok {
			// should apply this prefix to a member, not the channel
			// TODO: if the nick given is not a member of this channel, return false
			c.Members[params[pos]].ApplyMode(v)
			pos++
		} else {
			return false
		}
	}
	return true
}
