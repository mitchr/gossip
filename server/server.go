package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"iter"
	"log"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	cap "github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan"
	"github.com/mitchr/gossip/scan/msg"
	"github.com/mitchr/gossip/util"
	"github.com/pires/go-proxyproto"
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
	clients *util.SafeMap[string, *client.Client]

	// ChanType + name to channel
	channels *util.SafeMap[string, *channel.Channel]

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
		Config:   c,
		created:  time.Now(),
		clients:  util.NewSafeMap[string, *client.Client](),
		channels: util.NewSafeMap[string, *channel.Channel](),
		// keep this list sorted alphabetically
		supportedCaps: []cap.Cap{
			cap.AccountNotify,
			cap.AccountTag,
			cap.AwayNotify,
			cap.Batch,
			cap.CapNotify,
			cap.EchoMessage,
			cap.ExtendedJoin,
			cap.ExtendedMonitor,
			cap.InviteNotify,
			cap.LabeledResponses,
			cap.MessageTags,
			cap.MultiPrefix,
			cap.SASL,
			cap.ServerTime,
			cap.Setname,
			cap.UserhostInNames,
		},
		monitor: monitor{m: make(map[string]map[string]bool)},
	}

	err := s.loadDatabase(s.Datasource)
	if err != nil {
		return nil, err
	}

	s.listener, err = net.Listen("tcp", c.Port)
	if err != nil {
		return nil, err
	}
	if c.Proxy.Enabled {
		proxyListener := &proxyproto.Listener{Listener: s.listener}
		if len(c.Proxy.Whitelist) > 0 {
			proxyListener.Policy = proxyproto.MustStrictWhiteListPolicy(c.Proxy.Whitelist)
		}
		s.listener = proxyListener
	}

	if c.TLS.Enabled {
		if c.TLS.Proxy.Enabled {
			s.tlsListener, err = net.Listen("tcp", c.TLS.Port)
			if err != nil {
				return nil, err
			}

			proxyListener := &proxyproto.Listener{Listener: s.tlsListener}
			if len(c.TLS.Proxy.Whitelist) > 0 {
				proxyListener.Policy = proxyproto.MustStrictWhiteListPolicy(c.TLS.Proxy.Whitelist)
			}
			s.tlsListener = proxyListener
		} else {

			s.tlsListener, err = tls.Listen("tcp", c.TLS.Port, c.TLS.Config)
			if err != nil {
				return nil, err
			}
		}
		if c.TLS.STS.Enabled {
			s.supportedCaps = append(s.supportedCaps, cap.STS)
			sort.Slice(s.supportedCaps, func(i, j int) bool {
				return s.supportedCaps[i].Name < s.supportedCaps[j].Name
			})
		}
	}

	return s, nil
}

func (s *Server) hasCap(c string) bool {
	_, found := slices.BinarySearchFunc(s.supportedCaps, c, func(e cap.Cap, t string) int {
		if e.Name > t {
			return 1
		} else if e.Name < t {
			return -1
		}
		return 0
	})
	return found
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
	defer s.wg.Done()

	c, clientCtx, cancel := client.New(u, ctx)
	defer cancel()

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
	p := &scan.Parser{Lexer: scan.Lex(nil, msg.LexMessage)}

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

			p.Reset(buff)
			m, err := msg.Parse(p)

			if p.CheckUTF8Error() != nil {
				s.stdReply(c, FAIL, m.Command, "INVALID_UTF8", "", "Message rejected, your IRC software MUST use UTF-8 encoding on this network")
				errs <- p.CheckUTF8Error()
				continue
			} else if err == msg.ErrMsgSizeOverflow {
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
	return s.clients.Get(strings.ToLower(c))
}
func (s *Server) setClient(v *client.Client) {
	s.clients.Put(strings.ToLower(v.Nick), v)
}
func (s *Server) deleteClient(k string) {
	s.clients.Del(strings.ToLower(k))
}
func (s *Server) clientLen() int {
	return s.clients.Len()
}

func (s *Server) getChannel(c string) (*channel.Channel, bool) {
	return s.channels.Get(strings.ToLower(c))
}
func (s *Server) setChannel(v *channel.Channel) {
	s.channels.Put(strings.ToLower(v.String()), v)
}
func (s *Server) deleteChannel(k string) {
	s.channels.Del(strings.ToLower(k))
}
func (s *Server) channelLen() int {
	return s.channels.Len()
}

func (s *Server) channelsOf(c *client.Client) iter.Seq[*channel.Channel] {
	return func(yield func(*channel.Channel) bool) {
		for _, v := range s.channels.All() {
			if _, ok := v.GetMember(c.Nick); ok {
				if !yield(v) {
					return
				}
			}
		}
	}
}

func (s *Server) getChannelsClientInvitedTo(c *client.Client) iter.Seq[*channel.Channel] {
	return func(yield func(*channel.Channel) bool) {
		for _, v := range s.channels.All() {
			for _, in := range v.Invited {
				if strings.ToLower(c.Nick) == strings.ToLower(in) {
					if !yield(v) {
						return
					}
				}
			}
		}
	}
}

func (s *Server) haveChanInCommon(c1, c2 *client.Client) bool {
	for _, ch := range s.channels.All() {
		_, c1Belongs := ch.GetMember(c1.Nick)
		_, c2Belongs := ch.GetMember(c2.Nick)
		if c1Belongs && c2Belongs {
			return true
		}
	}
	return false
}
