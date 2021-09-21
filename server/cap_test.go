package server

import (
	"fmt"
	"testing"

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
	capBackup := cap.Caps
	cap.Caps = make(map[string]cap.Capability)
	cap.Caps["sasl"] = cap.Capability{"sasl", "PLAIN,EXTERNAL"}
	t.Run("TestCAPLS302Values", func(t *testing.T) {
		c.Write([]byte("CAP LS 302\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, ":gossip CAP bob LS :sasl=PLAIN,EXTERNAL\r\n", t)
	})

	// even if the client had initally shown support for >=302, still give
	// back un-302 values for an LS of lesser value
	t.Run("TestCAPLSValues", func(t *testing.T) {
		c.Write([]byte("CAP LS\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, ":gossip CAP bob LS :sasl\r\n", t)
	})
	cap.Caps = capBackup

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
	assertResponse(resp, "@+aaa=b :a!a@localhost TAGMSG :b\r\n", t)
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
