package client

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mitchr/gossip/cap"
	"github.com/mitchr/gossip/scan/msg"
)

type Client struct {
	net.Conn
	// true when the underlying connection is closed
	IsClosed bool

	Nick     string
	User     string
	Realname string
	Host     string

	// uxin timestamp when client first connects
	JoinTime int64
	// last time that client sent a succcessful message
	Idle time.Time

	*bufio.ReadWriter
	maxMsgSize int

	Mode              Mode
	AwayMsg           string
	ServerPassAttempt []byte
	RegSuspended      bool

	// Represents a set of IRCv3 capabilities
	Caps map[cap.Capability]bool
	// The maximum CAP version that this client supports. If no version is
	// explicity requested, this will be 0.
	CapVersion int

	// used to signal when client has successfully responded to server PING
	PONG chan struct{}

	// this lock is used when negotiating capabilities that modify the
	// client state in some way. most notably, when requesting
	// message-tags the client message size increases, so we need to do
	// this with mutual exclusion.
	capLock sync.Mutex

	grants chan bool
}

func New(conn net.Conn) *Client {
	now := time.Now()
	c := &Client{
		Conn:     conn,
		JoinTime: now.Unix(),
		Idle:     now,

		ReadWriter: bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
		maxMsgSize: 512,

		PONG:   make(chan struct{}, 1),
		Caps:   make(map[cap.Capability]bool),
		grants: make(chan bool, 10),
	}

	c.FillGrants()
	c.populateHostname()

	return c
}

// populateHostname does an rDNS lookup on the client's ip address. If
// there is an error, or the lookup takes too long, the client's ip
// address will be used as the default hostname.
func (c *Client) populateHostname() {
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())

	ch := make(chan string)
	go func() {
		names, err := net.LookupAddr(host)
		if err != nil {
			log.Println("unable to resolve hostname", host)
		}
		ch <- names[0]
	}()

	select {
	case <-time.After(time.Second * 5):
		c.Host = host
	case h := <-ch:
		c.Host = h
	}
}

func (c *Client) String() string {
	if c.User != "" {
		return fmt.Sprintf("%s!%s@%s", c.Nick, c.User, c.Host)
	} else if c.Host != "" {
		return fmt.Sprintf("%s@%s", c.Nick, c.Host)
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

// returns true if the client is connected over tls
func (c *Client) IsSecure() bool {
	_, ok := c.Conn.(*tls.Conn)
	return ok
}

// return the sha256 hash of the client's tls certificate. if the
// client is not connected via tls, or they have not provided a cert,
// return nil.
func (c *Client) CertificateFingerprint() (string, error) {
	if !c.IsSecure() {
		return "", errors.New("client is not connected over tls")
	}

	certs := c.Conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return "", errors.New("client has not provided a certificate")
	}

	sha := sha256.New()
	sha.Write(certs[0].Raw)
	return hex.EncodeToString(sha.Sum(nil)), nil
}

func (c *Client) CapsSet() string {
	caps := make([]string, len(c.Caps))
	i := 0
	for k := range c.Caps {
		caps[i] = k.String()
	}
	return strings.Join(caps, " ")
}

func (c *Client) SupportsCapVersion(v int) bool {
	return c.CapVersion >= v
}

func (c *Client) Close() error {
	c.IsClosed = true
	return c.Conn.Close()
}

var (
	ErrMsgSizeOverflow = errors.New("message too large")
	ErrFlood           = errors.New("flooding the server")
)

// Read until encountering a newline
func (c *Client) ReadMsg() (*msg.Message, error) {
	// as a form of flood control, ask for a grant before reading
	// each request
	err := c.requestGrant()
	if err != nil {
		return nil, err
	}

	c.capLock.Lock()
	read := make([]byte, c.maxMsgSize)
	c.capLock.Unlock()

	for n := 0; n < len(read); n++ {
		b, err := c.ReadByte()
		if err != nil {
			return nil, err
		}
		read[n] = b

		// accepted if we find a newline
		if b == '\n' {
			return msg.Parse(read[:n+1]), nil
		}
	}

	return nil, ErrMsgSizeOverflow
}

func (c *Client) Write(b []byte) (int, error) {
	return c.ReadWriter.Write(append(b, '\r', '\n'))
}

// requestGrant allows the client to process one message. If the client
// has no grants, this returns an error.
func (c *Client) requestGrant() error {
	select {
	case <-c.grants:
		return nil
	default:
		return ErrFlood
	}
}

// FillGrants fills the clients grant queue to the max.
func (c *Client) FillGrants() {
	for i := 0; i < 10; i++ {
		c.AddGrant()
	}
}

// Increment the grant counter by 1. If the client already has max
// grants, this does nothing.
func (c *Client) AddGrant() {
	select {
	case c.grants <- true:
	default:
		return
	}
}
