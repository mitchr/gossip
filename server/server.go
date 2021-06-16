package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

// freeze is used for testing. when locked, message execution is paused
// allowing a test to read the state of the server exclusively
var freeze sync.Mutex

type Server struct {
	*Config

	listener    net.Listener
	tlsListener net.Listener
	created     time.Time

	// nick to underlying client
	clients map[string]*client.Client
	// ChanType + name to channel
	channels map[string]*channel.Channel

	// a running count of connected users who are unregistered
	// (used for LUSER replies)
	unknownLock sync.Mutex
	unknowns    int

	// calling this cancel also cancels all the child client's contexts
	cancel   context.CancelFunc
	msgQueue chan func()
	wg       sync.WaitGroup
}

func New(c *Config) (*Server, error) {
	s := &Server{
		Config:   c,
		created:  time.Now(),
		clients:  make(map[string]*client.Client),
		channels: make(map[string]*channel.Channel),
		msgQueue: make(chan func(), 10),
	}

	var err error
	s.listener, err = net.Listen("tcp", c.Port)
	if err != nil {
		return nil, err
	}

	if c.TLS.Enabled {
		s.tlsListener, err = tls.Listen("tcp", c.TLS.Port, c.TLS.Config)
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (s *Server) startAccept(ctx context.Context, l net.Listener) {
	for {
		conn, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		s.wg.Add(1)
		go s.handleConn(conn, ctx)
	}
}

func (s *Server) Serve() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	go s.startAccept(ctx, s.listener)
	if s.tlsListener != nil {
		go s.startAccept(ctx, s.tlsListener)
	}

	// grabs messages from the queue and executes them in sequential order
	s.wg.Add(1)
	for {
		select {
		case msg := <-s.msgQueue:
			freeze.Lock()
			msg()
			freeze.Unlock()
		case <-ctx.Done():
			s.wg.Done()

			// empty all remaining messages from queue
			for m := range s.msgQueue {
				freeze.Lock()
				m()
				freeze.Unlock()
			}
			return
		}
	}
}

// gracefully shutdown server:
// 1. close listener so that we stop accepting more connections
// 2. s.cancel to exit serve loop
// 3. wait until all clients have canceled AND Serve() receives cancel signal
// 4. close s.msgQueue since we won't be receiving any more messages
// graceful shutdown from https://blog.golang.org/context
func (s *Server) Close() {
	s.listener.Close()
	if s.tlsListener != nil {
		s.tlsListener.Close()
	}
	s.cancel()
	s.wg.Wait()
	close(s.msgQueue)
}

func (s *Server) handleConn(u net.Conn, ctx context.Context) {
	clientCtx, cancel := context.WithCancel(ctx)
	c := client.New(u)

	s.unknownLock.Lock()
	s.unknowns++
	s.unknownLock.Unlock()

	// give a small window for client to register before kicking them off
	go func() {
		time.Sleep(time.Second * 10)
		if !c.Is(client.Registered) {
			s.ERROR(c, "Closing Link: Client failed to register in alloted time (10 seconds)")
			c.Flush()
			cancel()
		}
	}()

	// every 5 minutes, send PING
	// if client doesn't respond with a PONG in 10 seconds, kick them
	go func() {
		ticker := time.NewTicker(time.Minute * 5)
		for {
			select {
			case <-clientCtx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				fmt.Fprintf(c, ":%s PING %s\r\n", s.Name, c.Nick)
				c.Flush()

				select {
				case <-c.PONG:
				case <-time.After(time.Second * 10):
					s.ERROR(c, "Closing Link: PING timeout (300 seconds)")
					c.Flush()
					cancel()
					return
				}
			}
		}
	}()

	// every 2 seconds, give this client a grant
	go func() {
		for {
			select {
			case <-clientCtx.Done():
				return
			case <-time.After(time.Second * 2):
				c.AddGrant()
			}
		}
	}()

	// fetch a message from the client, parse it, then send it to the
	// server's message queue. This goroutine is implicitly closed when
	// clientCtx is canceled.
	go func() {
		for {
			// as a form of flood control, ask for a grant before reading
			// each request
			err := c.RequestGrant()
			if err != nil {
				// TODO: instead of kicking the client right away, maybe a
				// timeout would be more appropriate (atleast for the first 2
				// or 3 offenses)
				s.ERROR(c, "Flooding")
				c.Flush()
				cancel()
				return
			}

			// read until encountering a newline; the parser checks that \r exists
			msgBuf, err := c.ReadMsg()

			// client went past the 512 message length requirement
			if err == client.ErrMsgSizeOverflow {
				// TODO: discourage client from multiple buffer overflows in a
				// row to try to prevent against denial of service attacks
				s.writeReply(c, c.Id(), ERR_INPUTTOOLONG)
				c.Flush()
				continue
			} else if err != nil {
				// either client closed its own connection, or they disconnected without quit
				cancel()
				return
			}

			msg := msg.Parse(msgBuf)
			if s.Debug {
				log.Println(msg)
			}

			// implicitly ignore all nil messages
			if msg != nil {
				s.msgQueue <- func() { s.executeMessage(msg, c) }
			}
		}
	}()

	<-clientCtx.Done()
	s.msgQueue <- func() {
		defer s.wg.Done()

		if !c.Is(client.Registered) {
			s.unknownLock.Lock()
			s.unknowns--
			s.unknownLock.Unlock()
			c.Close()
		} else {
			// client was kicked off without first sending a QUIT
			// command, so we need to remove them from all the channels they
			// are still connected to
			QUIT(s, c, &msg.Message{Command: "PART", Params: []string{"Client left without saying goodbye :("}})
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

func (s *Server) haveChanInCommon(c1, c2 *client.Client) bool {
	for _, ch := range s.channels {
		_, c1Belongs := ch.GetMember(c1.Nick)
		_, c2Belongs := ch.GetMember(c2.Nick)
		if c1Belongs && c2Belongs {
			return true
		}
	}
	return false
}
