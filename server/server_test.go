package server

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func TestTLS(t *testing.T) {
	err := generateX509()
	if err != nil {
		t.Fatal(err)
	}
	configJSON := `{"network": "cafeteria",
	"name": "gossip",
	"port": ":6667",
	"tls": {
		"enabled": true,
		"port": ":6697",
		"pubkey": "public.cert",
		"privkey": "private.key"
	},
	"motd": ""}`
	ioutil.WriteFile("config.json", []byte(configJSON), 0664)
	defer func() { // cleanup files
		os.Remove("public.cert")
		os.Remove("private.key")
		os.Remove("config.json")
	}()

	conf, err := NewConfig("config.json")
	if err != nil {
		t.Fatal(err)
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

// Creates a PEM-encoded public/private certificate files called "public.cert" and "private.key"
func generateX509() error {
	// generate simple cert
	// mostly taken from src/crypto/tls/generate_cert.go
	sNum, _ := rand.Int(rand.Reader, big.NewInt(128))
	template := x509.Certificate{
		SerialNumber: sNum,
		DNSNames:     []string{"gossip"},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute * 1),
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}

	certFile, err := os.Create("public.cert")
	if err != nil {
		return err
	}
	keyFile, err := os.Create("private.key")
	if err != nil {
		return err
	}

	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return nil
}
