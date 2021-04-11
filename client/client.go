package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

type Client struct {
	Nick       string
	User       string
	Realname   string
	Host       net.Addr
	Mode       Mode
	Registered bool

	conn   net.Conn
	reader *bufio.Reader

	ServerPassAttempt string
	RegSuspended      bool

	ExpectingPONG bool
	Cancel        context.CancelFunc // need to store for QUIT
}

// TODO: default values for Nick, User, and Realname? (maybe '*')
func New(conn net.Conn) *Client {
	c := &Client{
		Host: conn.RemoteAddr(),
		conn: conn,

		// only read 512 bytes at a time
		// TODO: an additional 512 bytes can be used for message tags, so
		// this limit will have to be modified to accomodate that
		reader: bufio.NewReaderSize(conn, 512),
	}

	// give a small window for client to register before kicking them off
	go func() {
		<-time.After(time.Second * 10)
		if !c.Registered {
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

// Write appends a crlf to the end of each message
func (c *Client) Write(i interface{}) (int, error) {
	switch b := i.(type) {
	case []byte:
		return c.conn.Write(append(b, []byte{'\r', '\n'}...))
	case string:
		return c.Write([]byte(b))
	}
	return 0, errors.New("Couldn't write: message parameter type unknown")
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
