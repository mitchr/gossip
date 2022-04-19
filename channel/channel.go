package channel

import (
	"errors"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/mode"
	"github.com/mitchr/gossip/scan/msg"
	"github.com/mitchr/gossip/scan/wild"
)

type ChanType rune

const (
	Remote ChanType = '#'
	Local  ChanType = '&'
)

type Channel struct {
	// Name is case-insensitive, stored internally in lower-case
	Name       string
	ChanType   ChanType
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
	Members     map[string]*Member
	MembersLock sync.RWMutex
}

func New(name string, t ChanType) *Channel {
	return &Channel{
		Name:     name,
		ChanType: t,
		Limit:    math.MaxInt,
		Members:  make(map[string]*Member),
	}
}

func (c *Channel) String() string {
	return string(c.ChanType) + c.Name
}

func (c *Channel) Len() int {
	c.MembersLock.RLock()
	defer c.MembersLock.RUnlock()

	return len(c.Members)
}

func (c *Channel) GetMember(m string) (*Member, bool) {
	c.MembersLock.RLock()
	defer c.MembersLock.RUnlock()

	mem, ok := c.Members[strings.ToLower(m)]
	return mem, ok
}
func (c *Channel) SetMember(v *Member) {
	c.MembersLock.Lock()
	defer c.MembersLock.Unlock()

	c.Members[strings.ToLower(v.Nick)] = v
}

func (c *Channel) DeleteMember(m string) {
	c.MembersLock.Lock()
	defer c.MembersLock.Unlock()

	delete(c.Members, strings.ToLower(m))
}

func (ch *Channel) ForAllMembersExcept(c *client.Client, f func(m *Member)) {
	ch.MembersLock.RLock()
	defer ch.MembersLock.RUnlock()
	for _, v := range ch.Members {
		if v.Client == c {
			continue
		}
		f(v)
	}
}

func (c *Channel) Modes() (modestr string, params []string) {
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
func (c *Channel) Write(b []byte) (int, error) {
	var n int
	var errStrings []string

	c.MembersLock.RLock()
	defer c.MembersLock.RUnlock()
	for _, v := range c.Members {
		written, err := v.Conn.Write(v.PrepareMessage(b))
		if err != nil {
			errStrings = append(errStrings, err.Error())
			log.Println(string(b), err)
		}
		n += written
	}

	return n, errors.New(strings.Join(errStrings, "\n"))
}

func (c *Channel) WriteMessage(m *msg.Message) {
	c.MembersLock.RLock()
	defer c.MembersLock.RUnlock()

	for _, v := range c.Members {
		v.WriteMessage(m)
		v.Flush()
	}
}

func (c *Channel) WriteMessageFrom(m *msg.Message, from *client.Client) {
	c.MembersLock.RLock()
	defer c.MembersLock.RUnlock()

	for _, v := range c.Members {
		v.WriteMessageFrom(m, from)
		v.Flush()
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
//	3. their nick has been given an INVITE
//	4. if they have not been given an INVITE, their nickmask is in the inviteException list
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
				if wild.Match(strings.ToLower(k), strings.ToLower(c.Nick)) { // nickmask is an exception, so admit
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
func (c *Channel) ApplyMode(m mode.Mode) (string, error) {
	var applied string
	if m.Type == mode.Add {
		applied = "+"
	} else if m.Type == mode.Remove {
		applied = "-"
	}

	if p, ok := channelLetter[m.ModeChar]; ok {
		applied += string(m.ModeChar)

		// special branch for key validation
		if m.ModeChar == 'k' && m.Type == mode.Add {
			if !keyIsValid(m.Param) {
				return "", fmt.Errorf("%w%s", ErrInvalidKey, applied)
			}
		}

		if (p.addConsumes && m.Type == mode.Add) || (p.remConsumes && m.Type == mode.Remove) {
			if m.Param == "" { // mode should have a param but doesn't
				return "", fmt.Errorf(":%w%s", ErrNeedMoreParams, applied)
			} else {
				applied += " " + m.Param
			}
		}
		p.apply(c, m.Param, m.Type == mode.Add)
	} else if _, ok := memberLetter[m.ModeChar]; ok { // should apply this prefix to a member, not the channel
		// all user MODE changes should have a param
		if m.Param == "" {
			return "", fmt.Errorf(":%w%s", ErrNeedMoreParams, applied+string(m.ModeChar))
		}

		member, belongs := c.GetMember(m.Param)
		if !belongs {
			// give back given nick
			return "", fmt.Errorf("%w%s", ErrNotInChan, m.Param)
		}

		member.ApplyMode(m)
		applied += string(m.ModeChar) + " " + m.Param
	} else {
		// give back error with the unknown mode char
		return "", fmt.Errorf("%w%s", ErrUnknownMode, string(m.ModeChar))
	}

	return applied, nil
}

func keyIsValid(key string) bool {
	return key != "" && !strings.ContainsAny(key, "\000\r\n\t\v ") && len(key) < 23
}

// PopulateModeParams associates the given params with the Params field
// of the Modes. Params are looked at in index order, so something like
// "MODE #test +ok alice password" will associate 'o' with 'alice' and
// 'k' with 'password'. This skips mode characters that do not take an
// argument, and unknown mode characters.
func PopulateModeParams(modes []mode.Mode, params []string) {
	pos := 0
	for i, m := range modes {
		// stop looking for params if there are none left; this is good
		// because if we are expecting more params, that error will occur in ApplyMode
		if pos > len(params)-1 {
			return
		}
		if p, ok := channelLetter[m.ModeChar]; ok { // is channel mode
			if (m.Type == mode.Add && p.addConsumes) || (m.Type == mode.Remove && p.remConsumes) {
				modes[i].Param = params[pos]
				pos++
			}
		} else if _, ok := memberLetter[m.ModeChar]; ok {
			modes[i].Param = params[pos]
			pos++
		}
	}
}
