package server

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
)

func TestRegistration(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	t.Run("RegisterClient", func(t *testing.T) {
		conn, _ := connectAndRegister("alice", "Alice Smith")
		defer conn.Close()

		// check to see if server is in correct state
		c := s.Clients["alice"]
		if c.Nick != "alice" {
			t.Errorf("Nick registered incorrectly. Got %s\n", c.Nick)
		}
		if c.User != "alice" {
			t.Errorf("User registered incorrectly. Got %s\n", c.User)
		}
		if c.Realname != "Alice Smith" {
			t.Errorf("Real name registered incorrectly. Got %s\n", c.Realname)
		}
		if !c.Registered {
			t.Error("Client not registered")
		}
	})
}

func TestQUIT(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, _ := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, _ := connectAndRegister("bob", "Bob Smith")
	defer c2.Close()
	c1.Write([]byte("QUIT\r\n"))
	c2.Write([]byte("QUIT\r\n"))

	if !poll(&s.Clients, 0) {
		t.Error("client could not quit")
	}
}

func TestChannelCreation(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob Smith")
	defer c2.Close()
	c1.Write([]byte("JOIN #local\r\n"))
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #local\r\n"))
	r2.ReadBytes('\n')
	r1.ReadBytes('\n') // alice reading bob's join msg

	if !poll(&s.Channels, 1) {
		t.Fatal("Could not create channel")
	}

	t.Run("TestChannelPART", func(t *testing.T) {
		// c1 leaves, c2 should receive a PARTing message from them
		c1.Write([]byte("PART #local :Goodbye\r\n"))
		response, _ := r2.ReadBytes('\n')
		assertResponse(response, fmt.Sprintf("%s PART #local :Goodbye\r\n", s.Clients["alice"]), t)
	})

	t.Run("TestChannelDestruction", func(t *testing.T) {
		c2.Write([]byte("PART #local\r\n"))

		if !poll(&s.Channels, 0) {
			t.Error("Could not destroy channel")
		}
	})
}

func TestTOPIC(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice", "Alice Smith")
	defer c.Close()

	c.Write([]byte("JOIN &test\r\n"))
	r.ReadBytes('\n')

	c.Write([]byte("TOPIC &test\r\n"))
	c.Write([]byte("TOPIC &test :This is a test\r\n"))
	c.Write([]byte("TOPIC &test\r\n"))
	c.Write([]byte("TOPIC &test :\r\n"))
	c.Write([]byte("TOPIC &test\r\n"))

	unchanged, _ := r.ReadBytes('\n')
	assertResponse(unchanged, fmt.Sprintf(":%s 331 alice &test :No topic is set\r\n", s.Listener.Addr()), t)
	changed, _ := r.ReadBytes('\n')
	assertResponse(changed, fmt.Sprintf(":%s 332 alice &test :This is a test\r\n", s.Listener.Addr()), t)
	retrieve, _ := r.ReadBytes('\n')
	assertResponse(retrieve, fmt.Sprintf(":%s 332 alice &test :This is a test\r\n", s.Listener.Addr()), t)

	r.ReadBytes('\n')
	clear, _ := r.ReadBytes('\n')
	fmt.Println(string(clear))
	assertResponse(clear, fmt.Sprintf(":%s 331 alice &test :No topic is set\r\n", s.Listener.Addr()), t)
}

func TestPRIVMSG(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob Smith")
	defer c2.Close()
	c1.Write([]byte("JOIN #local\r\n"))
	c2.Write([]byte("JOIN #local\r\n"))
	r1.ReadBytes('\n')
	r2.ReadBytes('\n')

	t.Run("TestClientPRIVMSG", func(t *testing.T) {
		c1.Write([]byte("PRIVMSG bob :hello\r\n"))
		msgResp, _ := r2.ReadBytes('\n')
		fmt.Println(string(msgResp))
	})
	t.Run("TestChannelPRIVMSG", func(t *testing.T) {
		c1.Write([]byte("PRIVMSG #local :hello\r\n"))
		msgResp, _ := r2.ReadBytes('\n')
		fmt.Println(string(msgResp))
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
	for i := 0; i < 13; i++ {
		r.ReadBytes('\n')
	}

	return c, r
}

func assertResponse(resp []byte, eq string, t *testing.T) {
	if string(resp) != eq {
		t.Fail()
	}
}

func poll(s interface{}, eq interface{}) bool {
	c := make(chan bool)

	// start goroutine that continually checks pointer reference against
	// eq, and signals channel if true
	go func() {
		for {
			switch v := s.(type) {
			case *map[string]*client.Client:
				if len(*v) == eq {
					c <- true
					return
				}
			case *map[string]*channel.Channel:
				if len(*v) == eq {
					c <- true
					return
				}
			}
		}
	}()

	// returns true if c returns a value before 500 miliseconds have elapsed
	select {
	case <-c:
		return true
	case <-time.After(time.Millisecond * 500):
		return false
	}
}
