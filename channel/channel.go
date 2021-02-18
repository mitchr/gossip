package channel

import (
	"fmt"
	"strings"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/util"
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
	Clients  util.List
}

func New(name string, t ChanType) *Channel {
	return &Channel{name, t, util.NewList()}
}

func (c Channel) String() string {
	return string(c.ChanType) + c.Name
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
// TODO: race condition here if length of client changed during execution
func (c *Channel) Write(b interface{}) (int, error) {
	var n int
	var errStrings []string

	for i := 0; i < c.Clients.Len(); i++ {
		client := c.Clients.Get(i).(*client.Client)
		written, err := client.Write(b)

		n += written
		errStrings = append(errStrings, err.Error())
	}

	return n, fmt.Errorf(strings.Join(errStrings, "\n"))
}
