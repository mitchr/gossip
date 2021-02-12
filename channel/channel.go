package channel

import (
	"fmt"
	"strings"

	"github.com/mitchr/gossip/client"
)

type ChanType rune

const (
	Remote ChanType = '#'
	Local  ChanType = '&'
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

// Equals accepts two types of arguments: a Channel struct, or a string.
// If given a channel struct, it will compare against the name and type,
// whereas if given a string of the form "#chan" or "&chan" it will
// deduce the correct chan type and name
func (c Channel) Equals(i interface{}) bool {
	switch v := i.(type) {
	case Channel:
		return c.Name == v.Name && c.ChanType == v.ChanType
	case string:
		return c.Name == v[1:] && c.ChanType == ChanType(v[0])
	default:
		return false
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
