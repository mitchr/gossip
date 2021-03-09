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
	Nick     string
	User     string
	Realname string
	Host     net.Addr
	Mode     Mode

	ServerPassAttempt string
	BarredFromPass    bool // true if client has executed NICK/USER

	conn          net.Conn
	ExpectingPONG bool
	Cancel        context.CancelFunc // need to store for QUIT
	Registered    bool
}

// TODO: default values for Nick, User, and Realname? (maybe '*')
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

// wrap Read/Write/Close for the connection
func (c *Client) Write(i interface{}) (int, error) {
	switch b := i.(type) {
	case []byte:
		return c.conn.Write(append(b, []byte{'\r', '\n'}...))
	case string:
		return c.Write([]byte(b))
	}
	return 0, errors.New("Couldn't write: message parameter type unknown")
}

func (c *Client) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *Client) Close() error {
	return c.conn.Close()
}
