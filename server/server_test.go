package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/mitchr/gossip/channel"
)

func init() {
	log.SetFlags(log.Lshortfile)
}

func TestTLS(t *testing.T) {
	s, err := New(generateConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	clientCert := generateCert()
	c, err := tls.Dial("tcp", ":6697", &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)

	t.Run("TestRegisterFromTLSClient", func(t *testing.T) {
		c.Write([]byte("NICK alice\r\nUSER alice 0 0 :Alice Smith\r\n"))
		welcome, _ := r.ReadBytes('\n')
		assertResponse(welcome, fmt.Sprintf(":%s 001 alice :Welcome to the %s IRC Network alice!alice@localhost\r\n", s.Name, s.Network), t)
	})

	t.Run("TestWHOISCERTFP", func(t *testing.T) {
		c.Write([]byte("WHOIS alice\r\n"))
		resp, _ := readLines(r, 15)

		sha := sha256.Sum256(clientCert.Certificate[0])
		assertResponse(resp, fmt.Sprintf(":%s 276 alice alice :has client certificate fingerprint %s\r\n", s.Name, hex.EncodeToString(sha[:])), t)
	})

	t.Run("TestPRIVMSGFromInsecureToSecure", func(t *testing.T) {
		c2, r2 := connectAndRegister("bob")
		defer c2.Close()

		c.Write([]byte("PRIVMSG bob :hey\r\n"))
		msg, _ := r2.ReadBytes('\n')
		assertResponse(msg, ":alice!alice@localhost PRIVMSG bob :hey\r\n", t)
	})

}

func TestMessageSize(t *testing.T) {
	s, err := New(&Config{Network: "cafeteria", Name: "gossip", Port: ":6667"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	t.Run("TooLong", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		longMsg := make([]byte, 513)
		c.Write(longMsg)
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 417 * :Input line was too long\r\n", s.Name), t)
	})

	t.Run("JustRight", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		msg := []byte("PING ")
		zeros := make([]byte, 510-len(msg))
		for i := range zeros {
			zeros[i] = '0'
		}
		msg = append(msg, zeros...)
		msg = append(msg, '\r', '\n')
		c.Write(msg)
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":gossip PONG gossip %s\r\n", zeros), t)
	})

	t.Run("HugeTags", func(t *testing.T) {
		c, r := connectAndRegister("d")
		c.Write([]byte("CAP REQ message-tags\r\n"))
		r.ReadBytes('\n')

		tags := make([]byte, 8190)
		for i := range tags {
			tags[i] = 'a'
		}
		tags = append([]byte("@"), tags...)
		command := make([]byte, 512-7)
		for i := range command {
			command[i] = ' '
		}
		command = append(command, []byte(" TIME\r\n")...)
		tags = append(tags, command...)

		c.Write(tags)
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(ERR_INPUTTOOLONG, s.Name, "d"), t)
	})
}

func TestFlooding(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice")
	defer c.Close()

	for i := 0; i < 20; i++ {
		c.Write([]byte("NICK\r\n"))
		r.ReadBytes('\n')
	}
	c.Write([]byte("NICK\r\n"))
	flood, _ := r.ReadBytes('\n')
	assertResponse(flood, "ERROR :Flooding\r\n", t)
}

func TestWriteMultiline(t *testing.T) {
	s, err := New(&Config{Network: "cafeteria", Name: "gossip", Port: ":6667"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r, p := connect(s)
	defer p()

	c.Write([]byte("NICK alice\r\nUSER alice 0 0 :Alice\r\n"))
	resp, _ := r.ReadBytes('\n')
	alice, _ := s.getClient("alice")
	assertResponse(resp, fmt.Sprintf(":%s 001 alice :Welcome to the %s IRC Network %s\r\n", s.Name, s.Network, alice.String()), t)
}

func TestCaseInsensitivity(t *testing.T) {
	s, err := New(&Config{Name: "gossip", Port: ":6667"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
	defer c2.Close()

	t.Run("TestNickCaseInsensitive", func(t *testing.T) {
		c1.Write([]byte("NICK BOB\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 433 alice BOB :Nickname is already in use\r\n", s.Name), t)
		c1.Write([]byte("NICK boB\r\n"))
		resp, _ = r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 433 alice boB :Nickname is already in use\r\n", s.Name), t)
	})

	t.Run("TestChanCaseInsensitive", func(t *testing.T) {
		s.channels["#test"] = channel.New("test", '#')
		s.channels["#test"].SetMember(&channel.Member{Client: s.clients["alice"]})

		c2.Write([]byte("JOIN #tEsT\r\n"))
		r1.ReadBytes('\n')
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, ":bob!bob@localhost JOIN #test\r\n", t)
	})

	t.Run("TestCommandCaseInsensitive", func(t *testing.T) {
		c1.Write([]byte("who #test\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')

		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 315 alice #test :End of WHO list\r\n", s.Name), t)
	})
}

func TestUnicodeNICK(t *testing.T) {
	s, err := New(&Config{Name: "gossip", Port: ":6667", Network: "cafe"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r, p := connect(s)
	defer p()

	c.Write([]byte("NICK 🛩️\r\nUSER airplane 0 0 :A\r\n"))
	resp, _ := r.ReadBytes('\n')

	airplane := s.clients["🛩️"].String()
	assertResponse(resp, fmt.Sprintf(":%s 001 🛩️ :Welcome to the cafe IRC Network %s\r\n", s.Name, airplane), t)
}

func TestUnknownCount(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r, p := connect(s)
	defer p()

	// we send NICK and USER in separate parts here to ensure that that
	// getMessage has been started and therefore unknownCount was
	// incremented
	c.Write([]byte("NICK one\r\n"))

	if s.unknowns.Get() != 1 {
		t.Error("did not increment unknown count")
	}

	c.Write([]byte("USER 1 0 0 :1\r\n"))
	r.ReadBytes('\n')

	if s.unknowns.Get() != 0 {
		t.Error("did not decrement unknown count")
	}
}

func TestUTF8ONLY(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r, p := connect(s)
	defer p()

	utf16Encoded := utf16.Encode([]rune("NICK 🎉\r\n"))
	utf16EncodedToUtf8 := func(s []uint16) []byte {
		b := make([]byte, 0, len(s)*2)

		for _, v := range s {
			high := byte(v >> 8)
			low := byte(0x00ff & v)

			b = append(b, high, low)
		}
		return b
	}(utf16Encoded)

	c.Write(utf16EncodedToUtf8)
	errResp, _ := r.ReadBytes('\n')
	assertResponse(errResp, "ERROR :Messages must be encoded using UTF-8\r\n", t)
}

// a slow connection should not prevent other clients from receiving a message promptly
func TestSlowWriter(t *testing.T) {
	s, _ := New(conf)
	defer s.Close()
	go s.Serve()

	p := connectSlowWriter(s)
	defer p()
	c2, _ := connectAndRegister("a")
	defer c2.Close()
	c3, r3 := connectAndRegister("b")
	defer c3.Close()

	c2.Write([]byte("PRIVMSG slow,b :hello!\r\n"))
	resp, _ := r3.ReadBytes('\n')
	assertResponse(resp, ":a!a@localhost PRIVMSG b :hello!\r\n", t)
}

func BenchmarkRegistrationSurge(b *testing.B) {
	s, _ := New(conf)
	defer s.Close()
	go s.Serve()

	names := make([]string, 5000)
	names[0] = "a"
	for i := 1; i < 5000; i++ {
		previous := names[i-1]
		lastByteOfPrevious := previous[len(previous)-1]
		// last name generated ended with z, should restart at 'a'
		if lastByteOfPrevious == 'z' {
			names[i] = previous + "a"
		} else {
			names[i] = previous[:len(previous)-1] + (string(lastByteOfPrevious + 1))
		}
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c, _ := connectAndRegister(string(names[i]))
		c.Close()
	}
}

// given a nick and a realname, return a connection that is already
// registered and a bufio.Reader that has already read past all the
// initial connection rigamarole (RPL's, MOTD, etc.)
func connectAndRegister(nick string) (net.Conn, *bufio.Reader) {
	c, _ := net.Dial("tcp", ":6667")

	c.Write([]byte("NICK " + nick + "\r\nUSER " + nick + " 0 0 :" + nick + "\r\n"))

	r := bufio.NewReader(c)
	readLines(r, 13)

	return c, r
}

func readUntilPONG(r *bufio.Reader) {
	for resp, _ := r.ReadString('\n'); !strings.Contains(resp, "PONG"); resp, _ = r.ReadString('\n') {
	}
}

// Read i lines from the buffer, returning the last one read
func readLines(r *bufio.Reader, i int) ([]byte, error) {
	for n := 0; n < i-1; n++ {
		r.ReadBytes('\n')
	}
	return r.ReadBytes('\n')
}

// connect can be used for mocking simple connections that don't need
// to test any tcp/tls specific portions of the server
func connect(s *Server) (net.Conn, *bufio.Reader, context.CancelFunc) {
	serverHandle, c := net.Pipe()
	r := bufio.NewReader(c)

	ctx, cancel := context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.handleConn(serverHandle, ctx)

	var p context.CancelFunc = func() {
		cancel()
		c.Close()
		// serverHandle.Close()
	}

	return c, r, p
}

func assertResponse(resp []byte, eq string, t *testing.T) {
	t.Helper()

	if string(resp) != eq {
		t.Error("expected", eq, "got", string(resp))
	}
}

// Creates a PEM-encoded public/private certificate
func generateCert() tls.Certificate {
	sNum, _ := rand.Int(rand.Reader, big.NewInt(128))
	template := x509.Certificate{
		SerialNumber: sNum,
		DNSNames:     []string{"gossip"},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute * 1),
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)

	certPem := new(bytes.Buffer)
	keyPem := new(bytes.Buffer)
	pem.Encode(certPem, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	pem.Encode(keyPem, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	cert, _ := tls.X509KeyPair(certPem.Bytes(), keyPem.Bytes())
	return cert
}

func generateConfig() *Config {
	cert := generateCert()

	c := &Config{}
	c.Name = "gossip"
	c.Port = ":6667"
	c.TLS.Config = &tls.Config{ClientAuth: tls.RequestClientCert, Certificates: []tls.Certificate{cert}}
	c.TLS.Enabled = true
	c.TLS.Port = ":6697"

	return c
}

// slowWriter is a net.Conn that sleeps on write when block == true
type slowWriter struct {
	net.Conn
	block bool
}

func (s slowWriter) Write(b []byte) (int, error) {
	if s.block {
		time.Sleep(time.Millisecond * 300)
	}
	return s.Conn.Write(b)
}
func (s slowWriter) RemoteAddr() net.Addr { return s }
func (s slowWriter) Network() string      { return "0.0.0.0" }
func (s slowWriter) String() string       { return s.Network() }

func connectSlowWriter(s *Server) context.CancelFunc {
	serverHandle, c := net.Pipe()
	r := bufio.NewReader(c)
	slow := &slowWriter{Conn: serverHandle}
	ctx, cancel := context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.handleConn(slow, ctx)
	c.Write([]byte("NICK slow\r\nUSER slow 0 0 slow\r\n"))
	readLines(r, 13)
	slow.block = true

	return cancel
}
