package channel

import (
	"errors"
	"log"
	"strings"

	"github.com/mitchr/gossip/msg"
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

func (c *Channel) ApplyMode(b [2]string) bool {
	modeStr := b[0]
	modeArgs := b[1]

	add, sub := msg.ParseMode([]byte(modeStr))
	for _, v := range add {
		if p, ok := channelLetter[v]; ok {
			p(c, modeArgs, true)
			c.Modes += string(v)
		} else {
			return false
		}
	}

	for _, v := range sub {
		if p, ok := channelLetter[v]; ok {
			p(c, modeArgs, false)
			c.Modes = strings.Replace(c.Modes, string(v), "", -1)
		} else {
			return false
		}
	}
	return true
}
