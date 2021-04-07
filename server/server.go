package server

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

type Server struct {
	listener net.Listener
	created  time.Time
	password string
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

func New(port string) (*Server, error) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		return nil, err
	}
	return &Server{
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

	conChan := make(chan net.Conn)
	go func() { // accepts a connection and sends on chan
		for {
			conn, err := s.listener.Accept()
			if err == nil {
				conChan <- conn
			}
		}
	}()

	// grabs messages from the queue and executes them in sequential order
	go func() {
		for {
			(<-s.msgQueue)()
		}
	}()

	// capture OS interrupt signal so that we can gracefully shutdown server
	interrupt := make(chan os.Signal)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		s.Close()
	}()

	s.wg.Add(1)
	for {
		select {
		case <-ctx.Done():
			s.wg.Done()
			return
		case conn := <-conChan:
			s.wg.Add(1)
			go s.handleConn(conn, ctx)
		}
	}
}

// gracefully shutdown server:
// 1. close listener so that we stop accepting more connections
// 2. s.cancel to exit serve loop
// 3. wait until all clients have canceled AND Serve() receives cancel signal
// graceful shutdown from https://blog.golang.org/context
func (s *Server) Close() {
	s.listener.Close()
	s.cancel()
	s.wg.Wait()
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
				delete(s.clients, c.Nick)
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

func (s *Server) removeFromChannel(c *client.Client, ch *channel.Channel, msg string) {
	// if this was the last client in the channel, destroy it
	if len(ch.Members) == 1 {
		c.Write(msg)
		delete(s.channels, ch.String())
	} else {
		// message entire channel that client left
		ch.Write(msg)
		delete(ch.Members, c.Nick)
	}
}

func (s *Server) channelsOf(c *client.Client) []*channel.Channel {
	l := []*channel.Channel{}

	for _, v := range s.channels {
		if v.Members[c.Nick] != nil {
			l = append(l, v)
		}
	}
	return l
}
