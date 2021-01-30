package channel

import (
	"fmt"
	"strings"

	"github.com/mitchr/gossip/client"
)

type ChanType int

const (
	Remote ChanType = iota
	Local
)

// TODO: add some modes
type ChanMode int

const ()

type Channel struct {
	Name     string
	ChanType ChanType
	clients  *client.List
}

func New(name string, t ChanType) *Channel {
	return &Channel{Name: name, ChanType: t}
}

func (c Channel) Equals(i interface{}) bool {
	switch v := i.(type) {
	case Channel:
		return c.Name == v.Name && c.ChanType == v.ChanType
	default:
		return c.Name == v
	}
}

// broadcast message to each client in channel
func (c *Channel) Write(b []byte) (int, error) {
	var n int
	var errStrings []string

	for i := 0; i < c.clients.Len; i++ {
		client := c.clients.Get(i)
		written, err := client.Write(b)

		n += written
		errStrings = append(errStrings, err.Error())
	}

	return n, fmt.Errorf(strings.Join(errStrings, "\n"))
}
