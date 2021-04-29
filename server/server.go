package server

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

type Server struct {
	*Config

	listener net.Listener
	created  time.Time

	// nick to underlying client
	clients map[string]*client.Client
	// ChanType + name to channel
	channels map[string]*channel.Channel

	// a running count of connected users who are unregistered
	// (used for LUSER replies)
	unknowns int

	// calling this cancel also cancels all the child client's contexts
	cancel   context.CancelFunc
	msgQueue chan func()
	wg       sync.WaitGroup
}

func New(c *Config) (*Server, error) {
	l, err := net.Listen("tcp", c.Port)
	if err != nil {
		return nil, err
	}
	return &Server{
		Config:   c,
		listener: l,
		created:  time.Now(),
		clients:  make(map[string]*client.Client),
		channels: make(map[string]*channel.Channel),
		msgQueue: make(chan func(), 2),
	}, nil
}

func (s *Server) Serve() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	// start accepting connections
	go func() {
		for {
			conn, err := s.listener.Accept()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.wg.Add(1)
			go s.handleConn(conn, ctx)
		}
	}()

	// grabs messages from the queue and executes them in sequential order
	go func() {
		for msg, ok := <-s.msgQueue; ok; msg, ok = <-s.msgQueue {
			msg()
		}
	}()

	s.wg.Add(1)
	<-ctx.Done()
	s.wg.Done()
}

// gracefully shutdown server:
// 1. close listener so that we stop accepting more connections
// 2. s.cancel to exit serve loop
// 3. wait until all clients have canceled AND Serve() receives cancel signal
// 4. close s.msgQueue since we won't be receiving any more messages
// graceful shutdown from https://blog.golang.org/context
func (s *Server) Close() {
	s.listener.Close()
	s.cancel()
	s.wg.Wait()
	close(s.msgQueue)
}

func (s *Server) handleConn(u net.Conn, ctx context.Context) {
	c := client.New(u)
	clientCtx, cancel := context.WithCancel(ctx)
	c.Cancel = cancel

	s.unknowns++

	// continuously try to read from the client. this will implicitly end
	// when c.Cancel is called because the client will be closed
	input := make(chan []byte)
	go func() {
		for {
			// read until encountering a newline; the parser checks that \r exists
			msgBuf, err := c.ReadMsg()

			// client went past the 512 message length requirement
			if err == bufio.ErrBufferFull {
				// TODO: discourage client from multiple buffer overflows in a
				// row to try to prevent against denial of service attacks
				continue
			} else if err != nil {
				// either client closed its own connection, or they disconnected without quit
				c.Cancel()
				return
			}
			input <- msgBuf
		}
	}()

	for {
		select {
		case <-clientCtx.Done():
			s.msgQueue <- func() {
				if !c.Registered {
					s.unknowns--
				} else {
					// client may have been kicked off without first sending a QUIT
					// command, so we need to remove them from all the channels they
					// are still connected to
					QUIT(s, c, "Client left without saying goodbye :(")
				}

				c.Close()
				s.DeleteClient(c.Nick)
				s.wg.Done()
			}
			return
		case msgBuf := <-input:
			msg := msg.Parse(msgBuf)
			// implicitly ignore all nil messages
			if msg != nil {
				s.msgQueue <- func() { s.executeMessage(msg, c) }
			}
		}
	}
}

func (s *Server) GetClient(c string) (*client.Client, bool) {
	client, ok := s.clients[strings.ToLower(c)]
	return client, ok
}
func (s *Server) SetClient(k string, v *client.Client) { s.clients[strings.ToLower(k)] = v }
func (s *Server) DeleteClient(k string)                { delete(s.clients, strings.ToLower(k)) }

func (s *Server) GetChannel(c string) (*channel.Channel, bool) {
	ch, ok := s.channels[strings.ToLower(c)]
	return ch, ok
}
func (s *Server) SetChannel(k string, v *channel.Channel) { s.channels[strings.ToLower(k)] = v }
func (s *Server) DeleteChannel(k string)                  { delete(s.channels, strings.ToLower(k)) }

func (s *Server) channelsOf(c *client.Client) []*channel.Channel {
	l := []*channel.Channel{}

	for _, v := range s.channels {
		if _, ok := v.GetMember(c.Nick); ok {
			l = append(l, v)
		}
	}
	return l
}
