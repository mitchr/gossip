package server

import (
	"fmt"
	"testing"

	"github.com/mitchr/gossip/cap"
)

func TestREQ(t *testing.T) {
	conf := &Config{Name: "gossip", Port: ":6667"}

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

		if !s.clients["bob"].Caps[cap.MessageTags] {
			t.Error("Capability not added")
		}
	})

	t.Run("REQRemove", func(t *testing.T) {
		c.Write([]byte("CAP REQ -message-tags\r\n"))

		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s CAP bob ACK :-message-tags\r\n", s.Name), t)

		if len(s.clients["bob"].Caps) != 0 {
			t.Error("Capability not added")
		}
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

		if len(s.clients["bob"].Caps) != 0 {
			t.Error("Capability not added")
		}
	})
}
