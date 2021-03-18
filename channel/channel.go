package channel

import (
	"errors"
	"log"
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
	Ban    []string
	Except []string
	Key    string

	// map of Nick to undelying client
	Members map[string]*Member
}

func New(name string, t ChanType) *Channel {
	return &Channel{
		Name:     name,
		ChanType: t,
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

// Admit adds a client to this channel. A client c is admitted to enter
// a channel if their nickmask is not included in the banlist, or if
// they are in the banlist, they are in the except list. They are also
// admitted if adding this client does not put the channel over the
// chanlimit.
func (ch *Channel) Admit(c *client.Client) bool {
	for _, v := range ch.Ban {
		if wild.Match(v, c.String()) { // nickmask found in banlist
			for _, k := range ch.Except {
				if wild.Match(k, c.Nick) { // nickmask is an exception, so admit
					ch.Members[c.Nick] = &Member{Client: c}
					return true
				}
			}
			return false
		}
	}
	ch.Members[c.Nick] = &Member{Client: c}
	return true
}

func (c *Channel) ApplyMode(b []byte, params []string) bool {
	m := mode.Parse(b)

	// keep track of which param we are currently looking at
	pos := 0

	for _, v := range m {
		if p, ok := channelLetter[v.ModeChar]; ok {
			param := ""

			if v.Add {
				if p.addConsumes {
					param = params[pos]
					pos++
				}
				p.apply(c, param, true)
				c.Modes += string(v.ModeChar)
			} else {
				if p.remConsumes {
					param = params[pos]
					pos++
				}
				p.apply(c, param, false)
				c.Modes = strings.Replace(c.Modes, string(v.ModeChar), "", -1)
			}
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
