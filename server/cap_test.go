package server

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mitchr/gossip/cap"
)

func TestCap(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("a", "A")
	c.Write([]byte("CAP\r\nCAP fakesubcom\r\n"))
	invalid, _ := r.ReadBytes('\n')
	invalidSub, _ := r.ReadBytes('\n')
	assertResponse(invalid, ":gossip 410 a CAP :Invalid CAP command\r\n", t)
	assertResponse(invalidSub, ":gossip 410 a CAP fakesubcom :Invalid CAP command\r\n", t)
	defer c.Close()
}

func TestREQ(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("bob", "Bob")
	defer c.Close()

	t.Run("REQEmptyParam", func(t *testing.T) {
		c.Write([]byte("CAP REQ\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s CAP bob ACK :\r\n", s.Name), t)
	})

	t.Run("REQAdd", func(t *testing.T) {
		c.Write([]byte("CAP REQ message-tags\r\n"))

		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s CAP bob ACK :message-tags\r\n", s.Name), t)
	})

	t.Run("REQRemove", func(t *testing.T) {
		c.Write([]byte("CAP REQ -message-tags\r\n"))

		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s CAP bob ACK :-message-tags\r\n", s.Name), t)
	})

	t.Run("UnknownCapability", func(t *testing.T) {
		c.Write([]byte("CAP REQ :not-real\r\n"))

		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s CAP bob NAK :not-real\r\n", s.Name), t)
	})

	t.Run("MixedKnown+Unknown", func(t *testing.T) {
		c.Write([]byte("CAP REQ :message-tags not-real\r\n"))

		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s CAP bob NAK :message-tags not-real\r\n", s.Name), t)
	})
}

func TestCAP302(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("bob", "Bob")
	defer c.Close()

	c.Write([]byte("CAP LS 302\r\n"))
	r.ReadBytes('\n')

	// hacky way to test this because we don't have to worry about map
	// values being out of order
	t.Run("TestCAPLS302Values", func(t *testing.T) {
		c.Write([]byte("CAP LS 302\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, ":gossip CAP bob LS :cap-notify message-tags sasl=PLAIN,EXTERNAL,SCRAM\r\n", t)
	})

	// TODO: is this comment even true?
	// even if the client had initally shown support for >=302, still give
	// back un-302 values for an LS of lesser value
	t.Run("TestCAPLSValues", func(t *testing.T) {
		c.Write([]byte("CAP LS\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, ":gossip CAP bob LS :cap-notify message-tags sasl\r\n", t)
	})

	// TODO: test that cap version got updated
	t.Run("TestCAPUpgrade", func(t *testing.T) {
		c.Write([]byte("CAP LS 306\r\n"))
		r.ReadBytes('\n')
	})
}

func TestTAGMSG(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("a", "A")
	defer c1.Close()
	c2, r2 := connectAndRegister("b", "B")
	defer c2.Close()

	c1.Write([]byte("CAP REQ :message-tags\r\n"))
	c2.Write([]byte("CAP REQ :message-tags\r\n"))
	r1.ReadBytes('\n')
	r2.ReadBytes('\n')

	c1.Write([]byte("@+aaa=b TAGMSG b\r\n"))
	resp, _ := r2.ReadBytes('\n')
	assertResponse(resp, "@+aaa=b :a!a@localhost TAGMSG b\r\n", t)
}

func TestEchoMessage(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("a", "A")
	defer c1.Close()
	c2, r2 := connectAndRegister("b", "B")
	defer c2.Close()

	c1.Write([]byte("CAP REQ :echo-message\r\nPRIVMSG b test\r\n"))
	r1.ReadBytes('\n')

	resp, _ := r1.ReadBytes('\n')
	bResp, _ := r2.ReadBytes('\n')

	assertResponse(resp, ":a!a@localhost PRIVMSG b test\r\n", t)
	assertResponse(bResp, ":a!a@localhost PRIVMSG b test\r\n", t)
}

func TestMessageTags(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("a", "A")
	defer c1.Close()
	c2, r2 := connectAndRegister("b", "B")
	defer c2.Close()
	c1.Write([]byte("CAP REQ :message-tags\r\n"))
	r1.ReadBytes('\n')

	t.Run("TestSendToClientWithoutMessageTagCap", func(t *testing.T) {
		c1.Write([]byte("@+testTag PRIVMSG b :hey I attached a tag\r\n"))
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, ":a!a@localhost PRIVMSG b :hey I attached a tag\r\n", t)
	})

	t.Run("TestSendToClientWithMessageTagCap", func(t *testing.T) {
		c2.Write([]byte("CAP REQ :message-tags\r\n"))
		r2.ReadBytes('\n')

		c1.Write([]byte("@+testTag PRIVMSG b :hey I attached a tag\r\n"))
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, "@+testTag :a!a@localhost PRIVMSG b :hey I attached a tag\r\n", t)
	})
}

func TestServerTime(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("a", "A")
	defer c1.Close()

	c1.Write([]byte("CAP REQ :server-time\r\n"))
	resp, _ := r1.ReadBytes('\n')

	if !strings.Contains(string(resp), "@time=") {
		t.Error("did not include server-time in tags even though it was requested")
	}
}

func TestSTS(t *testing.T) {
	conf := generateConfig()
	conf.TLS.STS.Port = conf.TLS.Port[1:]
	conf.TLS.STS.Enabled = true

	s, err := New(conf)
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

	c.Write([]byte("NICK test\r\nUSER test 0 0 :realname\r\n"))
	c.Write([]byte("CAP LS 302\r\n"))
	for i := 0; i < 11; i++ {
		r.ReadBytes('\n')
	}

	resp, _ := r.ReadBytes('\n')
	// need to use contains here because the caps can be in any order
	if !strings.Contains(string(resp), "sts="+s.getSTSValue()) {
		t.Fail()
	}
}

func TestSTSConfig(t *testing.T) {
	var s Server
	s.Config = generateConfig()

	s.Config.TLS.STS.Port = "1010"
	s.Config.TLS.STS.Duration = time.Hour * 744 // 1 month
	s.Config.TLS.STS.Preload = true

	if s.getSTSValue() != fmt.Sprintf(cap.STS.Value, s.Config.TLS.STS.Port, s.Config.TLS.STS.Duration.Seconds())+",preload" {
		t.Fail()
	}
}
