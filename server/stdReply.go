package server

import (
	"fmt"
	"io"
)

type replyType string

const (
	FAIL replyType = "FAIL"
	WARN replyType = "WARN"
	NOTE replyType = "NOTE"
)

func (s *Server) stdReply(w io.Writer, rType replyType, command, code, context, description string) {
	if context == "" {
		fmt.Fprintf(w, "%s %s %s :%s\r\n", rType, command, code, description)
	} else {
		fmt.Fprintf(w, "%s %s %s %s :%s\r\n", rType, command, code, context, description)
	}
}
