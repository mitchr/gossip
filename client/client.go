package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/sasl"
	"github.com/mitchr/gossip/scan/msg"
)

type Client struct {
	conn net.Conn

	Nick     string
	User     string
	Realname string
	Host     string

	// uxin timestamp when client first connects
	JoinTime int64

	// last time that client sent a succcessful message
	idle int64

	msgBuf []byte

	Mode               Mode
	AwayMsg            string
	ServerPassAccepted bool
	RegSuspended       bool

	// Represents a set of IRCv3 capabilities
	Caps map[string]bool
	// The maximum CAP version that this client supports. If no version is
	// explicity requested, this will be 0.
	CapVersion int

	// Mechanism that is currently in use for this client
	SASLMech sasl.Mechanism

	// True if this client has authenticated using SASL
	IsAuthenticated bool

	// used to signal when client has successfully responded to server PING
	PONG chan struct{}

	AuthCtx []byte

	grants uint32
}

func New(conn net.Conn) *Client {
	now := time.Now()
	c := &Client{
		conn:     conn,
		JoinTime: now.Unix(),
		idle:     now.Unix(),

		msgBuf: make([]byte, 512),

		PONG: make(chan struct{}, 1),
		Caps: make(map[string]bool),

		SASLMech: sasl.None{},
	}

	c.FillGrants()
	c.Host = populateHostname(c.RemoteAddr().String())

	return c
}

// populateHostname does an rDNS lookup on the client's ip address. If
// there is an error, or the lookup takes too long, the client's ip
// address will be used as the default hostname.
func populateHostname(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if host == "" || err != nil {
		return addr
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond*300)
	defer cancel()

	var r net.Resolver
	names, err := r.LookupAddr(timeoutCtx, host)
	if err != nil || len(names) == 0 {
		// could not resolve hostname
		return host
	}

	return names[0]
}

func (c *Client) String() string {
	if c.User != "" {
		return c.Nick + "!" + c.User + "@" + c.Host
	} else if c.Host != "" {
		return c.Nick + "@" + c.Host
	} else if c.Nick != "" {
		return c.Nick
	} else {
		log.Println("client has no nick registered")
		return ""
	}
}

// An Id is used anywhere where a nick is requested in a reply. If
// Client.Nick is not set yet, then Id returns "*" as a generic
// placeholder.
func (c *Client) Id() string {
	if c.Nick != "" {
		return c.Nick
	}
	return "*"
}

func (c *Client) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// returns true if the client is connected over tls
func (c *Client) IsSecure() bool {
	_, ok := c.conn.(*tls.Conn)
	return ok
}

func (c *Client) Certificate() ([]byte, error) {
	if !c.IsSecure() {
		return nil, errors.New("client is not connected over tls")
	}

	certs := c.conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return nil, errors.New("client has not provided a certificate")
	}

	return certs[0].Raw, nil
}

func (c *Client) CertificateSha() ([sha256.Size]byte, error) {
	cert, err := c.Certificate()
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	return sha256.Sum256(cert), nil
}

// return a hex string of the sha256 hash of the client's tls
// certificate. if the client is not connected via tls, or they have
// not provided a cert, return nil.
func (c *Client) CertificateFingerprint() (string, error) {
	sha, err := c.CertificateSha()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sha[:]), nil
}

func (c *Client) CapsSet() string {
	caps := make([]string, len(c.Caps))
	i := 0
	for k := range c.Caps {
		caps[i] = k
		i++
	}
	return strings.Join(caps, " ")
}

func (c *Client) SupportsCapVersion(v int) bool {
	return c.CapVersion >= v
}

// Read until encountering a newline. If the client does not have any
// grants left, this returns an error.
func (c *Client) ReadMsg() ([]byte, error) {
	err := c.requestGrant()
	if err != nil {
		return nil, err
	}

	// buffer is full, clear it
	if c.msgBuf[len(c.msgBuf)-1] == '\n' {
		clear(c.msgBuf)
	}
	// clear previous message from buffer if there was one, and shift the
	// rest of the buffer towards the front
	newline := bytes.IndexByte(c.msgBuf, '\n')
	if newline != -1 {
		clear(c.msgBuf[0 : newline+1])
		copy(c.msgBuf, c.msgBuf[newline+1:])
	}

	n := 0
	for {
		newline := bytes.IndexByte(c.msgBuf, '\n')
		// found a newline, return buffer
		if newline != -1 {
			return c.msgBuf[:newline+1], nil
		}

		// buffer is full, clear it and send an error that we're flooded
		if n >= len(c.msgBuf) {
			clear(c.msgBuf)
			return nil, msg.ErrMsgSizeOverflow
		}

		r, err := c.conn.Read(c.msgBuf[n:])
		if err != nil {
			return nil, err
		}
		n += r
	}
}

func (c *Client) Write(b []byte) (int, error) {
	if err := c.conn.SetWriteDeadline(time.Now().Add(time.Millisecond * 250)); err != nil {
		return 0, err
	}

	return c.conn.Write(b)
}

const timeFormat string = "2006-01-02T15:04:05.999Z"

func (c *Client) WriteMessage(m msg.Msg) {
	if c.Caps[capability.ServerTime.Name] {
		m.AddTag("time", time.Now().UTC().Format(timeFormat))
	}

	c.Write(m.Bytes())
}

func (c *Client) WriteMessageFrom(m msg.Msg, from *Client) {
	if from.Is(Bot) {
		m.AddTag("bot", "")
	}

	if !c.HasMessageTags() {
		m = m.RemoveAllTags()
	}

	// if from == "*", then we assume that the sender has no authn
	if from.SASLMech.Authn() != "*" && c.Caps[capability.AccountTag.Name] {
		m.AddTag("account", from.SASLMech.Authn())
	}

	c.WriteMessage(m)
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) UpdateIdleTime(t time.Time) {
	atomic.StoreInt64(&c.idle, t.Unix())
}
func (c *Client) IdleTime() time.Time {
	return time.Unix(atomic.LoadInt64(&c.idle), 0)
}

const maxGrants = 20

var ErrFlood = errors.New("Flooding")

// requestGrant allows the client to process one message. If the client
// has no grants, this returns an error.
func (c *Client) requestGrant() error {
	for {
		g := atomic.LoadUint32(&c.grants)
		if g == 0 {
			return ErrFlood
		}

		if atomic.CompareAndSwapUint32(&c.grants, g, g-1) {
			return nil
		}
	}
}

// FillGrants fills the clients grant queue to the max.
func (c *Client) FillGrants() {
	atomic.StoreUint32(&c.grants, maxGrants)
}

// Increment the grant counter by 1. If the client already has max
// grants, this does nothing.
func (c *Client) AddGrant() {
	for {
		g := atomic.LoadUint32(&c.grants)
		if g == maxGrants {
			return
		}

		if atomic.CompareAndSwapUint32(&c.grants, g, g+1) {
			return
		}
	}
}
