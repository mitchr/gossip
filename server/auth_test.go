package server

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/mitchr/gossip/sasl/external"
	"github.com/mitchr/gossip/sasl/plain"
)

func TestREGISTER(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	conn, r := connectAndRegister("alice", "Alice Smith")
	defer conn.Close()

	conn.Write([]byte("REGISTER PASS pass1\r\n"))
	resp, _ := r.ReadBytes('\n')

	assertResponse(resp, "NOTICE Registered\r\n", t)
}

func TestAUTHENTICATE(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	plainCred := plain.NewCredential("tim", "tanstaaftanstaaf")
	s.db.Exec("INSERT INTO sasl_plain VALUES(?, ?)", plainCred.Username, plainCred.Pass)

	t.Run("TestAUTHENTICATEAfterRegister", func(t *testing.T) {
		c, r := connectAndRegister("a", "A")
		defer c.Close()

		c.Write([]byte("AUTHENTICATE PLAIN\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 904 a :SASL authentication failed\r\n", t)
	})

	t.Run("TestAUTHENTICATEAfterAuthenticate", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("CAP REQ sasl\r\nAUTHENTICATE PLAIN\r\n"))
		r.ReadBytes('\n') // cap ack
		r.ReadBytes('\n')

		clientFirst := []byte("\000tim\000tanstaaftanstaaf")
		firstEncoded := base64.StdEncoding.EncodeToString(clientFirst)

		c.Write([]byte("AUTHENTICATE " + firstEncoded + "\r\n"))
		r.ReadBytes('\n')
		r.ReadBytes('\n')

		c.Write([]byte("AUTHENTICATE PLAIN\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(ERR_SASLALREADY, s.Name, "*")+"\r\n", t)
	})

	t.Run("TestAUTHENTICATEAbort", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("CAP REQ sasl\r\nAUTHENTICATE PLAIN\r\nNICK b\r\nUSER b 0 0 :B\r\nCAP END\r\n"))
		r.ReadBytes('\n') // cap ack
		r.ReadBytes('\n') // authenticate +

		for i := 0; i < 11; i++ {
			r.ReadBytes('\n')
		}

		c.Write([]byte("AUTHENTICATE anything\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(ERR_SASLABORTED, s.Name, "b")+"\r\n", t)
	})

	t.Run("TestMissingParams", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("CAP REQ sasl\r\nAUTHENTICATE\r\n"))
		r.ReadBytes('\n')
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 461 * AUTHENTICATE :Not enough parameters\r\n", t)
	})

	t.Run("TestSASLAbort", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("CAP REQ sasl\r\nAUTHENTICATE *\r\n"))
		r.ReadBytes('\n')
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 906 * :SASL authentication aborted\r\n", t)
	})

	t.Run("TestUnknownMechanism", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("CAP REQ sasl\r\nAUTHENTICATE fakeMech\r\n"))
		r.ReadBytes('\n')
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 908 * PLAIN,EXTERNAL,SCRAM :are available SASL mechanisms\r\n", t)
	})
}

func TestAUTHENTICATEPLAIN(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r, p := connect(s)
	defer p()

	plainCred := plain.NewCredential("tim", "tanstaaftanstaaf")
	s.db.Exec("INSERT INTO sasl_plain VALUES(?, ?)", plainCred.Username, plainCred.Pass)

	c.Write([]byte("CAP REQ sasl\r\nNICK a\r\nUSER a 0 0 :A\r\nAUTHENTICATE PLAIN\r\n"))
	r.ReadBytes('\n')
	resp, _ := r.ReadBytes('\n')
	assertResponse(resp, ":gossip AUTHENTICATE +\r\n", t)

	clientFirst := []byte("\000tim\000tanstaaftanstaaf")
	firstEncoded := base64.StdEncoding.EncodeToString(clientFirst)

	c.Write([]byte("AUTHENTICATE " + firstEncoded + "\r\n"))
	serverFirst, _ := r.ReadBytes('\n')
	assertResponse(serverFirst, ":gossip 900 a a!a@pipe tim :You are now logged in as a\r\n", t)

	authenticationSuccess, _ := r.ReadBytes('\n')
	assertResponse(authenticationSuccess, ":gossip 903 a :SASL authentication successful\r\n", t)
}

func TestAUTHENTICATEEXTERNAL(t *testing.T) {
	s, err := New(generateConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	cert := generateCert()

	c, err := tls.Dial("tcp", ":6697", &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true})
	if err != nil {
		t.Error(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)

	cred := external.NewCredential("a", cert.Certificate[0])
	s.db.Exec("INSERT INTO sasl_external VALUES(?, ?)", cred.Username, cred.Cert)

	c.Write([]byte("CAP REQ sasl\r\nNICK a\r\nUSER a 0 0 :A\r\nAUTHENTICATE EXTERNAL\r\n"))
	r.ReadBytes('\n')
	resp, _ := r.ReadBytes('\n')
	assertResponse(resp, ":gossip AUTHENTICATE +\r\n", t)

	c.Write([]byte("AUTHENTICATE +\r\n"))
	resp, _ = r.ReadBytes('\n')
	assertResponse(resp, fmt.Sprintf(RPL_LOGGEDIN+"\r\n", s.Name, "a", "a!a@localhost", "a", "a"), t)

	resp, _ = r.ReadBytes('\n')
	assertResponse(resp, fmt.Sprintf(RPL_SASLSUCCESS+"\r\n", s.Name, "a"), t)
}

func TestAUTHENTICATESCRAM(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r, p := connect(s)
	defer p()

	plainCred := plain.NewCredential("tim", "tanstaaftanstaaf")
	s.db.Exec("INSERT INTO sasl_plain VALUES(?, ?)", plainCred.Username, plainCred.Pass)

	c.Write([]byte("CAP REQ sasl\r\nNICK a\r\nUSER a 0 0 :A\r\nAUTHENTICATE SCRAM\r\n"))
	r.ReadBytes('\n')
	resp, _ := r.ReadBytes('\n')
	assertResponse(resp, ":gossip AUTHENTICATE +\r\n", t)
}
