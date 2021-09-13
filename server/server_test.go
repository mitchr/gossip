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
	"testing"
	"time"

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
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		resp, _ := r.ReadBytes('\n')

		sha := sha256.New()
		sha.Write(clientCert.Certificate[0])
		assertResponse(resp, fmt.Sprintf(":%s 276 alice alice :has client certificate fingerprint %s\r\n", s.Name, hex.EncodeToString(sha.Sum(nil))), t)
	})

	t.Run("TestPRIVMSGFromInsecureToSecure", func(t *testing.T) {
		c2, r2 := connectAndRegister("bob", "Bob Smith")
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

	c, r, p := connect(s)
	defer p()

	t.Run("TooLong", func(t *testing.T) {
		longMsg := make([]byte, 513)
		c.Write(longMsg)
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 417 * :Input line was too long\r\n", s.Name), t)
	})

	// TODO
	t.Run("JustRight", func(t *testing.T) {
		t.Skip()
		msg := make([]byte, 512)
		msg[511] = '\n'
		c.Write(msg)
	})
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
	alice := s.clients["alice"].String()
	assertResponse(resp, fmt.Sprintf(":%s 001 alice :Welcome to the %s IRC Network %s\r\n", s.Name, s.Network, alice), t)
}

func TestCaseInsensitivity(t *testing.T) {
	s, err := New(&Config{Name: "gossip", Port: ":6667"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob Smith")
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
		s.channels["#test"].Members["alice"] = &channel.Member{Client: s.clients["alice"]}

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

func BenchmarkRegistrationSurge(b *testing.B) {
	s, _ := New(conf)
	defer s.Close()
	go s.Serve()

	b.ResetTimer()
	name := []byte{'a'}
	for i := 0; i < b.N; i++ {
		c, _ := connectAndRegister(string(name), string(name))
		defer c.Close()
		if name[len(name)-1] == 'z' {
			name[len(name)-1] = 'a'
			name = append(name, 'a')
		} else {
			name[len(name)-1]++
		}
	}
}

// given a nick and a realname, return a connection that is already
// registered and a bufio.Reader that has already read past all the
// initial connection rigamarole (RPL's, MOTD, etc.)
func connectAndRegister(nick, realname string) (net.Conn, *bufio.Reader) {
	c, _ := net.Dial("tcp", ":6667")

	c.Write([]byte("NICK " + nick + "\r\n"))
	c.Write([]byte("USER " + nick + " 0 0 :" + realname + "\r\n"))

	r := bufio.NewReader(c)
	for i := 0; i < 11; i++ {
		r.ReadBytes('\n')
	}

	return c, r
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
