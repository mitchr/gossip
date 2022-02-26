package client

import (
	"bufio"
	"context"
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

	"github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/sasl"
	"github.com/mitchr/gossip/scan/msg"
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

	*bufio.ReadWriter
	writeLock     sync.Mutex
	msgSizeChange chan int
	msgBuf        []byte

	Mode              Mode
	AwayMsg           string
	ServerPassAttempt []byte
	RegSuspended      bool

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

	grants    int
	grantLock sync.Mutex
}

func New(conn net.Conn) *Client {
	now := time.Now()
	c := &Client{
		Conn:     conn,
		JoinTime: now.Unix(),
		Idle:     now,

		ReadWriter:    bufio.NewReadWriter(bufio.NewReaderSize(conn, 512), bufio.NewWriter(conn)),
		msgSizeChange: make(chan int, 1),
		msgBuf:        make([]byte, 0, 512),

		PONG: make(chan struct{}, 1),
		Caps: make(map[string]bool),
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

	timeoutCtx, cancel := context.WithTimeout(context.TODO(), time.Millisecond*300)
	defer cancel()
	if err != nil {
		return host
	}

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

func (c *Client) Certificate() ([]byte, error) {
	if !c.IsSecure() {
		return nil, errors.New("client is not connected over tls")
	}

	certs := c.Conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return nil, errors.New("client has not provided a certificate")
	}

	return certs[0].Raw, nil
}

func (c *Client) CertificateSha() ([]byte, error) {
	cert, err := c.Certificate()
	if err != nil {
		return nil, err
	}

	sha := sha256.New()
	sha.Write(cert)
	return sha.Sum(nil), nil
}

// return a hex string of the sha256 hash of the client's tls
// certificate. if the client is not connected via tls, or they have
// not provided a cert, return nil.
func (c *Client) CertificateFingerprint() (string, error) {
	sha, err := c.CertificateSha()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sha), nil
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

	c.msgBuf = c.msgBuf[:0] // clear
	n := 0
	for n < cap(c.msgBuf) {
		// when the client adds or removes the 'message-tags' capability,
		// the maximum message size will change. by checking this signal
		// before every byte, we avoid the case where message1 requests
		// message-tags, and the reading of a possible message2 is blocked
		// on Read before the buffer has been increased.
		select {
		case size := <-c.msgSizeChange:
			resizeBuffer(c.msgBuf, size)
		default:
			b, err := c.ReadByte()
			if err != nil {
				return nil, err
			}
			c.msgBuf = append(c.msgBuf, b)

			// accepted if we find a newline
			if b == '\n' {
				return c.msgBuf, nil
			}
			n++
		}
	}
	return nil, msg.ErrMsgSizeOverflow
}

func (c *Client) Write(b []byte) (int, error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	prepared := c.PrepareMessage(b)
	return c.ReadWriter.Write(prepared)
}

func resizeBuffer(b []byte, size int) {
	// requesting a smaller capacity
	if size < cap(b) {
		length := len(b)

		// truncate existing data in buffer to number of bytes specified by 'size'
		if length > size {
			length = size
		}
		b = b[:length]
	}
	temp := make([]byte, len(b), size)
	copy(temp, b)
	b = temp
}

const timeFormat string = "2006-01-02T15:04:05.999Z"

func (c *Client) PrepareMessage(b []byte) []byte {
	temp := b
	if c.Caps[capability.ServerTime.Name] {
		serverTime := "@time=" + time.Now().UTC().Format(timeFormat) + " "
		temp = append([]byte(serverTime), temp...)
	}
	temp = append(temp, '\r', '\n')

	return temp
}

func (c *Client) Flush() error {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	return c.ReadWriter.Flush()
}

const maxGrants = 10

var ErrFlood = errors.New("flooding the server")

// requestGrant allows the client to process one message. If the client
// has no grants, this returns an error.
func (c *Client) requestGrant() error {
	c.grantLock.Lock()
	defer c.grantLock.Unlock()

	if c.grants == 0 {
		return ErrFlood
	}

	c.grants--
	return nil
}

// FillGrants fills the clients grant queue to the max.
func (c *Client) FillGrants() {
	c.grantLock.Lock()
	defer c.grantLock.Unlock()

	c.grants = maxGrants
}

// Increment the grant counter by 1. If the client already has max
// grants, this does nothing.
func (c *Client) AddGrant() {
	c.grantLock.Lock()
	defer c.grantLock.Unlock()

	if c.grants == maxGrants {
		return
	}
	c.grants++
}
