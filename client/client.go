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

	"github.com/mitchr/gossip/server/cap"
)

type Client struct {
	Nick     string
	User     string
	Realname string
	Host     net.Addr

	// uxin timestamp when client first connects
	JoinTime int64
	// last time that client sent a succcessful message
	Idle time.Time

	conn   net.Conn
	reader *bufio.Reader

	Mode              Mode
	AwayMsg           string
	ServerPassAttempt string
	RegSuspended      bool

	// Represents a set of IRCv3 capabilities
	Caps map[cap.Capability]bool

	ExpectingPONG bool
	Cancel        context.CancelFunc // need to store for QUIT
}

// TODO: default values for Nick, User, and Realname? (maybe '*')
func New(conn net.Conn) *Client {
	now := time.Now()
	c := &Client{
		Host:     conn.RemoteAddr(),
		conn:     conn,
		JoinTime: now.Unix(),
		Idle:     now,

		// only read 512 bytes at a time
		// TODO: an additional 512 bytes can be used for message tags, so
		// this limit will have to be modified to accomodate that
		reader: bufio.NewReaderSize(conn, 512),

		Caps: make(map[cap.Capability]bool),
	}

	// give a small window for client to register before kicking them off
	go func() {
		time.Sleep(time.Second * 10)
		if !c.Is(Registered) {
			c.Write("ERROR :Closing Link: Client failed to register in alloted time")
			c.Cancel()
			return
		}
	}()

	return c
}

func (c Client) String() string {
	if c.User != "" {
		return fmt.Sprintf("%s!%s@%s", c.Nick, c.User, c.Host)
	} else if c.Host.String() != "" {
		return fmt.Sprintf("%s@%s", c.Nick, c.Host)
	} else if c.Nick != "" {
		return c.Nick
	} else {
		log.Println("client has no nick registered")
		return ""
	}
}

func (c *Client) CapsSet() string {
	caps := make([]string, len(c.Caps))
	i := 0
	for k := range c.Caps {
		caps[i] = string(k)
	}
	return strings.Join(caps, " ")
}

// Write appends a crlf to the end of each message
func (c *Client) Write(i interface{}) (int, error) {
	switch b := i.(type) {
	case []byte:
		return c.conn.Write(append(b, []byte{'\r', '\n'}...))
	case string:
		return c.Write([]byte(b))
	default:
		return 0, errors.New("Couldn't write: message parameter type unknown")
	}
}

// Read until encountering a newline
func (c *Client) ReadMsg() ([]byte, error) {
	b, err := c.reader.ReadSlice('\n')

	// need to copy because ReadSlice reuses the slice pointer on the next read
	tmp := make([]byte, len(b))
	copy(tmp, b)
	return tmp, err
}

func (c *Client) Close() error {
	return c.conn.Close()
}
