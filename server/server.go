package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/util"
)

// A msgPair consists of a message and the client that sent it
type msgPair struct {
	m *message
	c *client.Client
}

type Server struct {
	Listener net.Listener
	Clients  util.List
	Created  time.Time
	Channels util.List

	// calling this cancel also cancels all the child client's contexts
	cancel   context.CancelFunc
	msgQueue chan msgPair
	msgLock  *sync.Mutex
	wg       sync.WaitGroup
}

func New(port string) (*Server, error) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		return nil, err
	}
	return &Server{
		Listener: l,
		Created:  time.Now(),
		// Clients:  util.NewList(),
		// Channels: util.NewList(),
		msgQueue: make(chan msgPair, 2),
		msgLock:  new(sync.Mutex),
	}, nil
}

func (s *Server) Serve() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	conChan := make(chan net.Conn)
	go func() { // accepts a connection and sends on chan
		for {
			conn, err := s.Listener.Accept()
			if err == nil {
				conChan <- conn
			}
		}
	}()

	go func() {
		for {
			msg := <-s.msgQueue
			s.msgLock.Lock()
			s.executeMessage(msg.m, msg.c)
			s.msgLock.Unlock()
		}
	}()

	s.wg.Add(1)
	for {
		select {
		case <-ctx.Done():
			s.wg.Done()
			return
		case conn := <-conChan:
			u := client.New(conn)
			clientCtx, cancel := context.WithCancel(ctx)
			u.Cancel = cancel

			s.msgLock.Lock()
			s.Clients.Add(u)
			s.msgLock.Unlock()

			s.wg.Add(1)
			go func() {
				s.handleClient(u, clientCtx)
				s.wg.Done()
			}()
		}
	}
}

// gracefully shutdown server:
// 1. close listener so that we stop accepting more connections
// 2. s.cancel to exit serve loop
// 3. wait until all clients have canceled AND Serve() receives cancel signal
// graceful shutdown from https://blog.golang.org/context
func (s *Server) Close() {
	s.Listener.Close()
	s.cancel()
	s.wg.Wait()
}

func (s *Server) handleClient(c *client.Client, ctx context.Context) {
	input := make(chan []byte)

	// continuously try to read from the client
	go func() {
		reader := bufio.NewReader(c)
		for {
			// read until encountering a newline; the parser checks that \r exists
			msgBuf, err := reader.ReadBytes('\n')
			if err != nil {
				// TODO: do something different if encountering a certain err? (io.EOF, net.OpErr)
				// either client closed its own connection, or they disconnected without quit
				c.Cancel()
				return
			} else {
				input <- msgBuf
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			s.msgLock.Lock()
			defer s.msgLock.Unlock()

			// client may have been kicked off without first sending a QUIT
			// command, so we need to remove them from all the channels they
			// are still connected to
			for _, v := range s.getAllChannelsForClient(c) {
				s.removeClientFromChannel(c, v, fmt.Sprintf(":%s QUIT :Client left without saying goodbye :(\r\n", c.Prefix()))
			}

			c.Close()
			s.Clients.Remove(c)
			return
		case msgBuf := <-input:
			msg := parse(lex(msgBuf))
			// implicitly ignore all nil messages
			if msg != nil {
				s.msgQueue <- msgPair{msg, c}
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
