package server

import (
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

type replyType string

const (
	FAIL replyType = "FAIL"
	WARN replyType = "WARN"
	NOTE replyType = "NOTE"
)

func (s *Server) stdReply(c *client.Client, rType replyType, command, code, context, description string) {
	c.WriteMessage(msg.New(nil, "", "", "", string(rType), []string{command, code, description}, true))
}
