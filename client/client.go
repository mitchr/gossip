package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

type Client struct {
	Nick        string
	User        string
	Realname    string
	Host        net.Addr
	conn        net.Conn
	idleTimeout time.Time
	Cancel      context.CancelFunc // need to store for QUIT

	// True if client is registered (nick/user passed)
	Registered bool
}

func New(conn net.Conn) *Client {
	c := &Client{
		Host: conn.RemoteAddr(),
		conn: conn,
	}

	// give a small window for client to register before kicking them off
	go func() {
		<-time.After(time.Second * 10)
		if !c.Registered {
			// TODO: send a QUIT message to this client with reason?
			c.Cancel()
			return
	}
	}()

	return c
}

func (c Client) Equals(i interface{}) bool {
	switch v := i.(type) {
	case Client:
		return c.Nick == v.Nick
	case *Client:
		return c.Nick == v.Nick
	default:
		return c.Nick == v
	}
}

func (c *Client) Prefix() string {
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
