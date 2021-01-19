package server

import (
	"fmt"

	"github.com/mitchr/gossip/client"
)

type numeric uint

const (
	RPL_WELCOME numeric = iota
	RPL_YOURHOST
	RPL_CREATED
	RPL_MYINFO
	RPL_ISUPPORT
)

func (s *Server) numericReply(c *client.Client, errCode numeric, errString string) error {
	_, err := c.Write(fmt.Errorf(":%s %d %s :%s\r\n", s.Listener.Addr().String(), errCode, c.Nick, errString))
	return err
}
