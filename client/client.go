package client

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type Client struct {
	Nick        string
	User        string
	Realname    string
	Host        net.Addr
	conn        net.Conn
	idleTimeout time.Time

	// list of channels that the client belongs to
	chanList []string

	// list of channels that client is a chanop for
	opList []string

	// True if client is registered (nick/user passed)
	Registered bool
}

func New(conn net.Conn) *Client {
	return &Client{
		Host: conn.RemoteAddr(),
		conn: conn,

		// when the connection begins, start a timeout that fires if the connection goes silent for x amount of time
		// before capability negotiation, this timeout will be short
		// after the user is established, give them more time
		idleTimeout: time.Now().Add(10 * time.Second),
	}
}

// wrap Read/Write/Close for the connection
func (c *Client) Write(i interface{}) (int, error) {
	switch b := i.(type) {
	case []byte:
		return c.conn.Write(b)
	case string:
		return c.conn.Write([]byte(b))
	case error:
		return c.conn.Write([]byte(b.Error()))
	}
	return 0, errors.New("Couldn't write: message parameter type unknown")
}

func (c *Client) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *Client) Close() error {
	return c.conn.Close()
}

// ping client and wait for PONG response
func (c *Client) PING(addr net.Addr) <-chan int {
	// send PING to client
	msg := fmt.Sprintf("PING :%s\r\n", addr.String())
	c.Write([]byte(msg))

	// next response should be a corresponding PONG
	resp := make([]byte, 256)

	// start timer to wait for PONG response
	c.conn.SetReadDeadline(c.idleTimeout)
	_, err := c.Read(resp)
	if err != nil {
		// time expired, close the connection
		c.Close()
	}
	// set time back to normal
	c.conn.SetReadDeadline(time.Time{})

	if !strings.Contains(string(resp), "PONG") {
		c.Close()
		return nil
	} else {
		pong := make(chan int, 1)
		pong <- 1
		return pong
	}
}
