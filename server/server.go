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

	"github.com/mitchr/gossip/cap"
	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

type Server struct {
	*Config

	listener    net.Listener
	tlsListener net.Listener
	created     time.Time

	// nick to underlying client
	clients    map[string]*client.Client
	clientLock sync.RWMutex

	// ChanType + name to channel
	channels map[string]*channel.Channel
	chanLock sync.RWMutex

	// a running count of connected users who are unregistered
	// (used for LUSER replies)
	unknownLock sync.Mutex
	unknowns    int

	supportedCaps []cap.Capability

	// calling this cancel also cancels all the child client's contexts
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(c *Config) (*Server, error) {
	s := &Server{
		Config:        c,
		created:       time.Now(),
		clients:       make(map[string]*client.Client),
		channels:      make(map[string]*channel.Channel),
		supportedCaps: []cap.Capability{cap.CapNotify, cap.EchoMessage, cap.MessageTags, cap.SASL, cap.ServerTime},
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
		if c.TLS.STS.Enabled {
			s.supportedCaps = append(s.supportedCaps, cap.STS)
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

	<-ctx.Done()
	s.wg.Wait()
}

// gracefully shutdown server:
// 1. close listener so that we stop accepting more connections
// 2. s.cancel to exit serve loop
// graceful shutdown from https://blog.golang.org/context
func (s *Server) Close() error {
	err := s.listener.Close()
	if err != nil {
		return err
	}
	if s.tlsListener != nil {
		err = s.tlsListener.Close()
		if err != nil {
			return err
		}
	}
	if s.cancel == nil {
		return errors.New("server context is nil; did you call Serve?")
	} else {
		s.cancel()
	}
	return nil
}

func (s *Server) handleConn(u net.Conn, ctx context.Context) {
	defer s.wg.Done()

	clientCtx, cancel := context.WithCancel(ctx)
	c := client.New(u)

	s.unknownLock.Lock()
	s.unknowns++
	s.unknownLock.Unlock()

	// give a small window for client to register before kicking them off
	go func() {
		time.Sleep(time.Second * 10)
		if !c.Is(client.Registered) {
			s.ERROR(c, "Closing Link: Client failed to register in allotted time (10 seconds)")
			c.Flush()
			cancel()
		}
	}()

	// fetch a message from the client, parse it, then execute it
	go func() {
		for {
			buff, err := c.ReadMsg()
			if s.Debug {
				log.Printf("Message: %s\nSent by ip: %s", string(buff), c.RemoteAddr().String())
			}

			if err == client.ErrFlood {
				// TODO: instead of kicking the client right away, maybe a
				// timeout would be more appropriate (atleast for the first 2
				// or 3 offenses)
				s.ERROR(c, "Flooding")
				c.Flush()
				cancel()
				return
			} else if err == client.ErrMsgSizeOverflow {
				// client went past the 512 message length requirement
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

			select {
			case <-clientCtx.Done():
				return
			default:
				tokens := msg.Lex(buff)
				msg := msg.Parse(tokens)
				// ignore all nil messages
				if msg != nil {
					s.executeMessage(msg, c)
				}
			}
		}
	}()

	pingTick := time.NewTicker(time.Minute * 5)  // every 5 minutes, send PING
	grantTick := time.NewTicker(time.Second * 2) // every 2 seconds, give this client a grant
	defer pingTick.Stop()
	defer grantTick.Stop()

	for {
		select {
		case <-clientCtx.Done():
			// client left/was kicked without first sending a QUIT command,
			// so send one for them
			QUIT(s, c, &msg.Message{Params: []string{"Client left without saying goodbye :("}})
			return
		case <-pingTick.C:
			fmt.Fprintf(c, ":%s PING %s", s.Name, c.Nick)
			c.Flush()

			select {
			case <-clientCtx.Done():
			case <-c.PONG:
			case <-time.After(time.Second * 10):
				s.ERROR(c, "Closing Link: PING timeout (300 seconds)")
				c.Flush()
				cancel()
			}
		case <-grantTick.C:
			c.AddGrant()
		}
	}
}

func (s *Server) GetClient(c string) (*client.Client, bool) {
	s.clientLock.RLock()
	defer s.clientLock.RUnlock()

	client, ok := s.clients[strings.ToLower(c)]
	return client, ok
}
func (s *Server) SetClient(k string, v *client.Client) {
	s.clientLock.Lock()
	defer s.clientLock.Unlock()

	s.clients[strings.ToLower(k)] = v
}
func (s *Server) DeleteClient(k string) {
	s.clientLock.Lock()
	defer s.clientLock.Unlock()

	delete(s.clients, strings.ToLower(k))
}
func (s *Server) ClientLen() int {
	s.clientLock.RLock()
	defer s.clientLock.RUnlock()

	return len(s.clients)
}

func (s *Server) GetChannel(c string) (*channel.Channel, bool) {
	s.chanLock.RLock()
	defer s.chanLock.RUnlock()

	ch, ok := s.channels[strings.ToLower(c)]
	return ch, ok
}
func (s *Server) SetChannel(k string, v *channel.Channel) {
	s.chanLock.Lock()
	defer s.chanLock.Unlock()

	s.channels[strings.ToLower(k)] = v
}
func (s *Server) DeleteChannel(k string) {
	s.chanLock.Lock()
	defer s.chanLock.Unlock()

	delete(s.channels, strings.ToLower(k))
}
func (s *Server) ChannelLen() int {
	s.chanLock.RLock()
	defer s.chanLock.RUnlock()

	return len(s.channels)
}

func (s *Server) channelsOf(c *client.Client) []*channel.Channel {
	l := []*channel.Channel{}

	s.chanLock.RLock()
	defer s.chanLock.RUnlock()

	for _, v := range s.channels {
		if _, ok := v.GetMember(c.Nick); ok {
			l = append(l, v)
		}
	}
	return l
}

func (s *Server) haveChanInCommon(c1, c2 *client.Client) bool {
	s.chanLock.RLock()
	defer s.chanLock.RUnlock()

	for _, ch := range s.channels {
		_, c1Belongs := ch.GetMember(c1.Nick)
		_, c2Belongs := ch.GetMember(c2.Nick)
		if c1Belongs && c2Belongs {
			return true
		}
	}
	return false
}
