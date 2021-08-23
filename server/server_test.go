package server

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"testing"
	"time"
)

func init() {
	log.SetFlags(log.Lshortfile)
}

func TestTLS(t *testing.T) {
	cert := generateCert()

	conf := &Config{
		Name: "gossip",
		Port: ":6667",
		TLS: struct {
			*tls.Config `json:"-"`
			Enabled     bool   `json:"enabled"`
			Port        string `json:"port"`
			Pubkey      string `json:"pubkey"`
			Privkey     string `json:"privkey"`
		}{
			Config:  &tls.Config{Certificates: []tls.Certificate{cert}},
			Enabled: true,
			Port:    ":6697",
		},
	}

	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, err := tls.Dial("tcp", ":6697", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	t.Run("TestRegisterFromTLSClient", func(t *testing.T) {
		c.Write([]byte("NICK alice\r\nUSER alice 0 0 :Alice Smith\r\n"))
		welcome, _ := bufio.NewReader(c).ReadBytes('\n')
		assertResponse(welcome, fmt.Sprintf(":%s 001 alice :Welcome to the %s IRC Network alice!alice@localhost\r\n", s.Name, s.Network), t)
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

	c, _ := net.Dial("tcp", ":6667")
	defer c.Close()
	r := bufio.NewReader(c)

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

	c, _ := net.Dial("tcp", ":6667")
	defer c.Close()

	c.Write([]byte("NICK alice\r\nUSER alice 0 0 :Alice\r\n"))
	resp, _ := bufio.NewReader(c).ReadBytes('\n')
	assertResponse(resp, fmt.Sprintf(":%s 001 alice :Welcome to the %s IRC Network alice!alice@localhost\r\n", s.Name, s.Network), t)
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
		c1.Write([]byte("JOIN #test\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
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

	c, _ := net.Dial("tcp", "localhost:6667")
	c.Write([]byte("NICK 🛩️\r\nUSER airplane 0 0 :A\r\n"))
	resp, _ := bufio.NewReader(c).ReadBytes('\n')
	assertResponse(resp, ":gossip 001 🛩️ :Welcome to the cafe IRC Network 🛩️!airplane@localhost\r\n", t)
}

func BenchmarkRegistrationSurge(b *testing.B) {
	s, _ := New(conf)
	defer s.Close()
	go s.Serve()

	b.ResetTimer()
	name := []byte{'a'}
	for i := 0; i < b.N; i++ {
		c, _ := connectAndRegister(string(name), string(name))
		go c.Close()
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
