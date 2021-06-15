package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mitchr/gossip/cap"
)

type Client struct {
	net.Conn

	Nick     string
	User     string
	Realname string
	Host     string

	// uxin timestamp when client first connects
	JoinTime int64
	// last time that client sent a succcessful message
	Idle time.Time

	rw         *bufio.ReadWriter
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

	ExpectingPONG bool
	Cancel        context.CancelFunc // need to store for QUIT

	// this lock is used when negotiating capabilities that modify the
	// client state in some way. most notably, when requesting
	// message-tags the client message size increases, so we need to do
	// this with mutual exclusion.
	capLock sync.Mutex

	grants chan bool
}

func New(ctx context.Context, conn net.Conn) *Client {
	now := time.Now()
	c := &Client{
		Conn:     conn,
		JoinTime: now.Unix(),
		Idle:     now,

		rw:         bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
		maxMsgSize: 512,

		Caps:   make(map[cap.Capability]bool),
		grants: make(chan bool, 10),
	}

	c.FillGrants()

	c.Host, _, _ = net.SplitHostPort(c.RemoteAddr().String())
	names, err := net.LookupAddr(c.Host)
	if err == nil {
		c.Host = names[0]
	}

	return c
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

func (c *Client) Write(b []byte) (int, error) { return c.rw.Write(b) }
func (c *Client) Flush() error                { return c.rw.Flush() }

var (
	ErrMsgSizeOverflow = errors.New("message too large")
	ErrFlood           = errors.New("flooding the server")
)

// Read until encountering a newline
func (c *Client) ReadMsg() ([]byte, error) {
	c.capLock.Lock()
	read := make([]byte, c.maxMsgSize)
	c.capLock.Unlock()

	for n := 0; n < len(read); n++ {
		b, err := c.rw.ReadByte()
		if err != nil {
			return nil, err
		}
		read[n] = b

		// accepted if we find a newline
		if b == '\n' {
			return read[:n+1], nil
		}
	}

	return nil, ErrMsgSizeOverflow
}

// RequestGrant allows the client to process one message. If the client
// has no grants, this returns an error.
func (c *Client) RequestGrant() error {
	select {
	case <-c.grants:
		return nil
	default:
		return ErrFlood
	}
}

// FillGrants fills the clients grant queue to the max.
func (c *Client) FillGrants() {
	for {
		select {
		case c.grants <- true:
		default:
			return
		}
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
