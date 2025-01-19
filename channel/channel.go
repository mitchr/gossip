package channel

import (
	"errors"
	"fmt"
	"iter"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/mode"
	"github.com/mitchr/gossip/scan/msg"
	"github.com/mitchr/gossip/scan/wild"
	"github.com/mitchr/gossip/util"
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

	CreatedAt time.Time

	Topic      string
	TopicSetBy *client.Client
	TopicSetAt time.Time

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
	Members *util.SafeMap[string, *Member]
}

func New(name string, t ChanType) *Channel {
	return &Channel{
		Name:      name,
		ChanType:  t,
		Limit:     math.MaxInt,
		Members:   util.NewSafeMap[string, *Member](),
		CreatedAt: time.Now(),
	}
}

func (c *Channel) String() string {
	return string(c.ChanType) + c.Name
}

func (c *Channel) Len() int {
	return c.Members.Len()
}

func (c *Channel) GetMember(m string) (*Member, bool) {
	mem, ok := c.Members.Get(strings.ToLower(m))
	return mem, ok
}
func (c *Channel) SetMember(v *Member) {
	c.Members.Put(v.Nick, v)
}

func (c *Channel) DeleteMember(m string) {
	c.Members.Del(strings.ToLower(m))
}

func (ch *Channel) All() iter.Seq[*Member] {
	return func(yield func(*Member) bool) {
		for _, m := range ch.Members.All() {
			if !yield(m) {
				return
			}
		}
	}
}

// AllExcept returns an iterator of all members in the channel except
// ones matching the except Client.
func (ch *Channel) AllExcept(except *client.Client) iter.Seq[*Member] {
	return func(yield func(*Member) bool) {
		for m := range ch.All() {
			if m.Client == except {
				continue
			}
			if !yield(m) {
				return
			}
		}
	}
}

func (c *Channel) Modes() (modestr string, params []string) {
	modestr = "+"
	if len(c.Ban) != 0 {
		modestr += "b"
		params = append(params, strings.Join(c.Ban, ","))
	}
	if len(c.BanExcept) != 0 {
		modestr += "e"
		params = append(params, strings.Join(c.BanExcept, ","))
	}
	if c.Limit != math.MaxInt {
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
// func (c *Channel) Write(b []byte) (int, error) {
// 	var n int
// 	var errStrings []string

// 	c.MembersLock.RLock()
// 	defer c.MembersLock.RUnlock()
// 	for _, v := range c.Members {
// 		written, err := v.Write(append(b, '\r', '\n'))
// 		if err != nil {
// 			errStrings = append(errStrings, err.Error())
// 			log.Println(string(b), err)
// 		}
// 		n += written
// 	}
// 	return n, errors.New(strings.Join(errStrings, "\n"))
// }

func (c *Channel) WriteMessage(m msg.Msg) {
	for v := range c.All() {
		v.WriteMessage(m)
	}
}

func (c *Channel) WriteMessageFrom(m msg.Msg, from *client.Client) {
	for v := range c.All() {
		v.WriteMessageFrom(m, from)
	}
}

var (
	ErrKeyMissing   = errors.New("ERR_BADCHANNELKEY")
	ErrLimitReached = errors.New("ERR_CHANNELISFULL")
	ErrNotInvited   = errors.New("ERR_INVITEONLYCHAN")
	ErrBanned       = errors.New("ERR_BANNEDFROMCHAN")
)

// Admit adds a client to this channel. A client c is admitted to enter
// a channel if:
//  1. If this channel has a key, the client supplies the correct key
//  2. admitting this client does not put the channel over the chanlimit
//  3. their nick has been given an INVITE
//  4. if they have not been given an INVITE, their nickmask is in the inviteException list
//  5. their nickmask is not included in the banlist
//  6. if they are in the banlist, they are in the except list
func (ch *Channel) Admit(c *client.Client, key string) error {
	if ch.Key != key {
		return ErrKeyMissing
	}
	if ch.Len() >= ch.Limit {
		return ErrLimitReached
	}

	if ch.Invite {
		for _, v := range ch.InviteExcept {
			// client doesn't need an invite, add them
			if wild.Match(strings.ToLower(v), strings.ToLower(c.String())) {
				ch.SetMember(&Member{Client: c})
				return nil
			}
		}
		for _, v := range ch.Invited {
			// client was invited
			if strings.ToLower(c.Nick) == strings.ToLower(v) {
				ch.SetMember(&Member{Client: c})
				return nil
			}
		}
		return ErrNotInvited
	}

	for _, v := range ch.Ban {
		if wild.Match(strings.ToLower(v), strings.ToLower(c.String())) { // nickmask found in banlist
			for _, k := range ch.BanExcept {
				if wild.Match(strings.ToLower(k), strings.ToLower(c.String())) { // nickmask is an exception, so admit
					ch.SetMember(&Member{Client: c})
					return nil
				}
			}
			return ErrBanned
		}
	}
	ch.SetMember(&Member{Client: c})
	return nil
}

var (
	ErrNeedMoreParams = errors.New("")
	ErrNotInChan      = errors.New("")
	ErrUnknownMode    = errors.New("")
	ErrInvalidKey     = errors.New("")
)

// ApplyMode applies the given mode to the channel. It does not
// verify that the sending client has the proper permissions to make
// those changes. It returns a modeStr if the mode was successfully applied.
func (c *Channel) ApplyMode(m mode.Mode) error {
	if p, ok := channelLetter[m.ModeChar]; ok {

		// special branch for key validation
		if m.ModeChar == 'k' && m.Type == mode.Add {
			if !keyIsValid(m.Param) {
				return fmt.Errorf("%w+k", ErrInvalidKey)
			}
		}

		if (p.addConsumes && m.Type == mode.Add) || (p.remConsumes && m.Type == mode.Remove) {
			if m.Param == "" { // mode should have a param but doesn't
				return fmt.Errorf(":%w%s", ErrNeedMoreParams, m)
			}
		}
		p.apply(c, m.Param, m.Type == mode.Add)
	} else if _, ok := memberLetter[m.ModeChar]; ok { // should apply this prefix to a member, not the channel
		// all user MODE changes should have a param
		if m.Param == "" {
			return fmt.Errorf(":%w%s", ErrNeedMoreParams, m)
		}

		member, belongs := c.GetMember(m.Param)
		if !belongs {
			// give back given nick
			return fmt.Errorf("%w%s", ErrNotInChan, m.Param)
		}

		member.ApplyMode(m)
	} else {
		// give back error with the unknown mode char
		return fmt.Errorf("%w%s", ErrUnknownMode, string(m.ModeChar))
	}

	return nil
}

func keyIsValid(key string) bool {
	return key != "" && !strings.ContainsAny(key, "\000\r\n\t\v ") && len(key) < 23
}

// PrepareModes performs two tasks:
//
//  1. associates the given params with the Params field of the modes.
//     Params are processed in index order, so something like "MODE
//     #test +ok alice password" will associate 'o' with 'alice' and 'k'
//     with 'password'. This skips unknown mode characters.
//  2. sets the Type of a mode to mode.List if there are no more params
//     left to be associated and that particular mode is listable
func PrepareModes(modes []mode.Mode, params []string) {
	pos := 0
	for _, p := range params {
		// no more modes left, we can ignore all other params
		if pos > len(modes)-1 {
			return
		}

		m := modes[pos]
		if f, ok := channelLetter[m.ModeChar]; ok {
			if (m.Type == mode.Add && f.addConsumes) || (m.Type == mode.Remove && f.remConsumes) {
				modes[pos].Param = p
				pos++
			}
		} else if _, ok := memberLetter[m.ModeChar]; ok {
			modes[pos].Param = p
			pos++
		}
	}

	// for remaining modes, check if they are listable
	for i, m := range modes[pos:] {
		if f, ok := channelLetter[m.ModeChar]; ok {
			if m.Type == mode.Add && f.canList {
				modes[i].Type = mode.List
			}
		}
	}
}
