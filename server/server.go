package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/util"
)

type Server struct {
	Listener net.Listener
	Clients  util.List
	Created  time.Time
	Channels util.List

	// calling this cancel also cancels all the child client's contexts
	cancel context.CancelFunc
}

func New(port string) (*Server, error) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		return nil, err
	}
	return &Server{
		Listener: l,
		Clients:  util.NewList(),
		Created:  time.Now(),
		Channels: util.NewList(),
	}, nil
}

func (s *Server) Serve() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	conChan := make(chan net.Conn)
	go func(c chan<- net.Conn) { // goroutine that accepts forever
		for {
			conn, err := s.Listener.Accept()
			if err == nil {
				c <- conn
			}
		}
	}(conChan)

	for {
		select {
		case <-ctx.Done():
			return
		case conn := <-conChan:
			u := client.New(conn)
			go s.handleClient(u, ctx)
		}
	}
}

// gracefully shutdown server:
// 1. close listener so that we stop accepting more connections
// 2. s.cancel to exit serve loop
// graceful shutdown from https://blog.golang.org/context
func (s *Server) Close() {
	s.Listener.Close()
	s.cancel()
}

func (s *Server) handleClient(c *client.Client, ctx context.Context) {
	clientCtx, cancel := context.WithCancel(ctx)
	c.Cancel = cancel

	// create entry for user
	s.Clients.Add(c)

	reader := bufio.NewReader(c)
	for {
		select {
		case <-clientCtx.Done():
			// client may have been kicked off without first sending a QUIT
			// command, so we need to handle removing them from all the
			// channels they are still connected to
			for _, v := range s.getAllChannelsForClient(c) {
				s.removeClientFromChannel(c, v, fmt.Sprintf(":%s QUIT :Client left without saying goodbye :(\r\n", c.Prefix()))
			}

			c.Close()
			s.Clients.Remove(c)
			return
		default:
			// read until we encounter a newline; the parser checks that \r exists
			msgBuf, err := reader.ReadBytes('\n')
			if err != nil { // TODO: do something different if encountering a certain err? (io.EOF, net.OpErr)
				// either client closed its own connection, or they disconnected without quit
				c.Cancel()
			} else {
				msg := parse(lex(msgBuf))
				// implicitly ignore all nil messages
				if msg != nil {
					s.executeMessage(msg, c)
				}
			}
		}
	}
}

func (s *Server) removeClientFromChannel(c *client.Client, ch *channel.Channel, msg string) {
	// if this was the last client in the channel, destroy it
	if ch.Clients.Len() == 1 {
		s.Channels.Remove(ch)
	} else {
		// message all remaining channel participants
		ch.Clients.Remove(c)
		ch.Write(msg)
	}
}

func (s *Server) getAllChannelsForClient(c *client.Client) []*channel.Channel {
	l := []*channel.Channel{}

	s.Channels.ForEach(func(e interface{}) {
		ch := e.(*channel.Channel)
		if ch.Clients.Find(c) != nil {
			l = append(l, ch)
		}
	})
	return l
}
