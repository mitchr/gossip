package channel

import (
	"errors"
	"log"
	"strings"

	"github.com/mitchr/gossip/scan/mode"
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
	Modes    string
	Key      string

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
