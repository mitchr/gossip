package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	cap "github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
	_ "modernc.org/sqlite"
)

type Server struct {
	*Config

	// database used for user account information
	db *sql.DB

	listener    net.Listener
	tlsListener net.Listener
	created     time.Time

	// nick to underlying client
	clients    map[string]*client.Client
	clientLock sync.RWMutex

	// ChanType + name to channel
	channels map[string]*channel.Channel
	chanLock sync.RWMutex

	joinLock sync.Mutex

	// a running count of connected users who are unregistered
	unknowns statistic

	// the largest number of clients ever connected to this server
	max statistic

	supportedCaps []cap.Cap
	whowasHistory whowasStack
	monitor       monitor

	wg sync.WaitGroup
}

func New(c *Config) (*Server, error) {
	s := &Server{
		Config:        c,
		created:       time.Now(),
		clients:       make(map[string]*client.Client),
		channels:      make(map[string]*channel.Channel),
		supportedCaps: []cap.Cap{cap.AccountNotify, cap.AccountTag, cap.AwayNotify, cap.Batch, cap.CapNotify, cap.Chghost, cap.EchoMessage, cap.ExtendedJoin, cap.LabeledResponses, cap.MessageTags, cap.MultiPrefix, cap.SASL, cap.ServerTime, cap.Setname, cap.UserhostInNames},
		monitor:       monitor{m: make(map[string]map[string]bool)},
	}

	err := s.loadDatabase(s.Datasource)
	if err != nil {
		return nil, err
	}

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

func (s *Server) hasCap(cap string) bool {
	for _, v := range s.supportedCaps {
		if v.Name == cap {
			return true
		}
	}
	return false
}

func (s *Server) loadDatabase(datasource string) error {
	var err error
	s.db, err = sql.Open("sqlite", datasource)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS sasl_plain(
		username TEXT,
		nick TEXT,
		pass BLOB,
		PRIMARY KEY(username)
	);
	
	CREATE TABLE IF NOT EXISTS sasl_external(
		username TEXT,
		nick TEXT,
		clientCert BLOB,
		PRIMARY KEY(username)
	);
	
	CREATE TABLE IF NOT EXISTS sasl_scram(
		username TEXT,
		nick TEXT,
		serverKey BLOB,
		storedKey BLOB,
		salt BLOB,
		iterations INTEGER,
		PRIMARY KEY(username)
	);
	
	CREATE TABLE IF NOT EXISTS channels(
		owner TEXT,
		chan TEXT
	)`)

	return err
}

func (s *Server) startAccept(ctx context.Context, cancel context.CancelFunc, l net.Listener) {
	for {
		conn, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			cancel()
			return
		}
		s.wg.Add(1)
		go s.handleConn(conn, ctx)
	}
}

func (s *Server) Serve() {
	ctx, cancel := context.WithCancel(context.Background())

	go s.startAccept(ctx, cancel, s.listener)
	if s.tlsListener != nil {
		go s.startAccept(ctx, cancel, s.tlsListener)
	}

	<-ctx.Done()
	s.wg.Wait()
}

// close listeners so that we stop accepting more connections
// this will implicitly cancel the server's context
// graceful shutdown from https://blog.golang.org/context
func (s *Server) Close() error {
	err := s.listener.Close()
	if err != nil {
		return err
	}
	if s.tlsListener != nil {
		return s.tlsListener.Close()
	}
	return nil
}

func (s *Server) handleConn(u net.Conn, ctx context.Context) {
	clientCtx, cancel := context.WithCancel(ctx)

	defer s.wg.Done()
	defer cancel()

	c := client.New(u)
	s.unknowns.Inc()

	errs := make(chan error)

	go startRegistrationTimer(c, errs)
	go s.getMessage(c, clientCtx, errs)

	pingTick := time.NewTicker(time.Minute * 5)  // every 5 minutes, send PING
	grantTick := time.NewTicker(time.Second * 2) // every 2 seconds, give this client a grant
	defer pingTick.Stop()
	defer grantTick.Stop()

	for {
		select {
		case <-clientCtx.Done():
			return
		case <-pingTick.C:
			c.WriteMessage(msg.New(nil, s.Name, "", "", "PING", []string{c.Nick}, false))
			go waitForPong(c, errs)
		case <-grantTick.C:
			c.AddGrant()
		case err := <-errs:
			if errors.Is(err, net.ErrClosed) {
				if _, ok := s.getClient(c.Nick); !ok {
					// network closed and client was already removed (or never
					// was added to begin with); no work to be done here
					return
				}
			}
			QUIT(s, c, &msg.Message{Params: []string{err.Error()}})
			return
		}
	}
}

var (
	ErrPingTimeout         = errors.New("Closing Link: PING timeout (300 seconds)")
	ErrRegistrationTimeout = errors.New("Closing Link: Client failed to register in allotted time (10 seconds)")
)

func waitForPong(c *client.Client, errs chan<- error) {
	select {
	case <-c.PONG:
	case <-time.After(time.Second * 10):
		errs <- ErrPingTimeout
	}
}

// give a small window for client to register before kicking them off
func startRegistrationTimer(c *client.Client, errs chan<- error) {
	time.Sleep(time.Second * 10)
	if !c.Is(client.Registered) {
		errs <- ErrRegistrationTimeout
	}
}

// fetch a message from the client and parse it
func (s *Server) getMessage(c *client.Client, ctx context.Context, errs chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buff, err := c.ReadMsg()
			if s.Debug && len(buff) != 0 {
				log.Printf("[%s]: %s\n", c.RemoteAddr(), string(bytes.TrimRight(buff, "\r\n")))
			}

			if err == msg.ErrMsgSizeOverflow {
				s.writeReply(c, ERR_INPUTTOOLONG)
				continue
			} else if err != nil {
				errs <- err
				continue
			}

			tokens, err := msg.Lex(buff)
			if err != nil {
				s.stdReply(c, FAIL, tokens.TryToExtractCommand(), "INVALID_UTF8", "", "Message rejected, your IRC software MUST use UTF-8 encoding on this network")
				errs <- err
				continue
			}

			m, err := msg.Parse(tokens)
			if err == msg.ErrMsgSizeOverflow {
				s.writeReply(c, ERR_INPUTTOOLONG)
			} else if errors.Unwrap(err) == msg.ErrParse {
				// silently ignore parse errors
			} else if err != nil {
				errs <- err
			}

			if m != nil {
				s.executeMessage(m, c)
			}
		}
	}
}

func (s *Server) getClient(c string) (*client.Client, bool) {
	s.clientLock.RLock()
	defer s.clientLock.RUnlock()

	client, ok := s.clients[strings.ToLower(c)]
	return client, ok
}
func (s *Server) setClient(v *client.Client) {
	s.clientLock.Lock()
	defer s.clientLock.Unlock()

	s.clients[strings.ToLower(v.Nick)] = v
}
func (s *Server) deleteClient(k string) {
	s.clientLock.Lock()
	defer s.clientLock.Unlock()

	delete(s.clients, strings.ToLower(k))
}
func (s *Server) clientLen() int {
	s.clientLock.RLock()
	defer s.clientLock.RUnlock()

	return len(s.clients)
}

func (s *Server) getChannel(c string) (*channel.Channel, bool) {
	s.chanLock.RLock()
	defer s.chanLock.RUnlock()

	ch, ok := s.channels[strings.ToLower(c)]
	return ch, ok
}
func (s *Server) setChannel(v *channel.Channel) {
	s.chanLock.Lock()
	defer s.chanLock.Unlock()

	s.channels[strings.ToLower(v.String())] = v
}
func (s *Server) deleteChannel(k string) {
	s.chanLock.Lock()
	defer s.chanLock.Unlock()

	delete(s.channels, strings.ToLower(k))
}
func (s *Server) channelLen() int {
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

func (s *Server) getChannelsClientInvitedTo(c *client.Client) []*channel.Channel {
	l := []*channel.Channel{}

	s.chanLock.RLock()
	defer s.chanLock.RUnlock()

	for _, v := range s.channels {
		for _, in := range v.Invited {
			if strings.ToLower(c.Nick) == strings.ToLower(in) {
				l = append(l, v)
			}
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
