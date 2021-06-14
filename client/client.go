package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
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

	rw *bufio.ReadWriter
	// reader     *bufio.Reader
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
}

func New(conn net.Conn) *Client {
	now := time.Now()
	c := &Client{
		Conn:     conn,
		JoinTime: now.Unix(),
		Idle:     now,

		rw:         bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
		maxMsgSize: 512,

		Caps: make(map[cap.Capability]bool),
	}

	c.Host, _, _ = net.SplitHostPort(c.RemoteAddr().String())
	names, err := net.LookupAddr(c.Host)
	if err == nil {
		c.Host = names[0]
	}

	// give a small window for client to register before kicking them off
	go func() {
		time.Sleep(time.Second * 10)
		if !c.Is(Registered) {
			fmt.Fprint(c, "ERROR :Closing Link: Client failed to register in alloted time (10 seconds)\r\n")
			c.Flush()
			c.Cancel()
		}
	}()

	return c
}

func (c Client) String() string {
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
func (c Client) Id() string {
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

func (c Client) SupportsCapVersion(v int) bool {
	return c.CapVersion >= v
}

var ErrMsgSizeOverflow = errors.New("message too large")

func (c *Client) Write(b []byte) (int, error) { return c.rw.Write(b) }
func (c *Client) Flush() error                { return c.rw.Flush() }

// Read until encountering a newline
func (c *Client) ReadMsg() ([]byte, error) {
	read := make([]byte, c.maxMsgSize)
	for n := 0; n < c.maxMsgSize; n++ {
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
