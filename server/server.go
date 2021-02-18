package server

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
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

	quit chan bool
	wg   sync.WaitGroup
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
		quit:     make(chan bool),
		wg:       sync.WaitGroup{},
	}, nil
}

func (s *Server) Serve() {
	for {
		// wait for a connection to the server
		// (block until one is received)
		conn, err := s.Listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Println(err)
			}
			continue
		}

		u := client.New(conn)

		// each client gets own goroutine for handling
		s.wg.Add(1)
		go func() {
			s.handleClient(u)
			s.wg.Done()
		}()
	}
}

// gracefully shutdown server:
// 1. close s.quit so that s stops listening for more connections
// 2. close s.listener; we are assured that there are no pending
//		connections because we have already stopped listening
// 3. wait for all existing clients to finish being handled
// thanks to these two posts about gracefully shutdown patterns in go:
// https://eli.thegreenplace.net/2020/graceful-shutdown-of-a-tcp-server-in-go/
// https://forum.golangbridge.org/t/correct-shutdown-of-net-listener/8705
func (s *Server) Close() {
	close(s.quit)
	s.Listener.Close()
	s.wg.Wait()
}

// TODO: when s.quit closes, force all clients to finish handling;
// either instantly force them off with a preceeding closure message,
// or give a small timeout window
func (s *Server) handleClient(c *client.Client) {
	// create entry for user
	s.Clients.Add(c)

	reader := bufio.NewReader(c)
	for {
		// read until we encounter a newline
		// really we should have \r\n, but we allow the parser to check that \r exists
		// also this removes the 512 byte message length limit, so we should consider if this is a meaningful regression
		// client could send so much data that the server crashes?
		msgBuf, err := reader.ReadBytes('\n')

		if err != nil {
			if err == io.EOF {
				// client has closed connection, so we need to remove them from the user list
			} else if operr, ok := err.(*net.OpError); ok {
				// there was some kind of network error
				fmt.Println(operr)
			} else {
				// not sure what happened!
				fmt.Println(err)
			}
			c.Close()
			s.Clients.Remove(c)
			return
		}

		msg := parse(lex(msgBuf))
		if msg == nil {
			log.Println("message is nil; ignored")
		} else {
			s.executeMessage(msg, c)
		}
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
