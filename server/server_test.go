package server

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/util"
)

func TestRegistration(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	conn, err := net.Dial("tcp", ":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	t.Run("RegisterClient", func(t *testing.T) {
		_, err := conn.Write([]byte("NICK alice\r\n"))
		if err != nil {
			t.Error(err)
		}

		_, err = conn.Write([]byte("USER alice 0 * :Alice Smith\r\n"))
		if err != nil {
			t.Error(err)
		}

		r := bufio.NewReader(conn)
		welcome, err := r.ReadBytes('\n')
		if err != nil {
			t.Error(err)
		}
		fmt.Println(string(welcome))

		host, err := r.ReadBytes('\n')
		if err != nil {
			t.Error(err)
		}
		fmt.Println(string(host))

		created, err := r.ReadBytes('\n')
		if err != nil {
			t.Error(err)
		}
		fmt.Println(string(created))

		// check to see if server is in correct state
		c := s.Clients.Get(0).(*client.Client)

		if c == nil {
			t.Fatal("No client connection made")
		}
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

	if !wfc(&s.Clients, 0) {
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

	c1, _ := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, _ := connectAndRegister("bob", "Bob Smith")
	defer c2.Close()
	c1.Write([]byte("JOIN #local\r\n"))
	c2.Write([]byte("JOIN #local\r\n"))

	if !wfc(&s.Channels, 1) {
		t.Fatal("Could not create channel")
	}

	t.Run("TestChannelDestruction", func(t *testing.T) {
		c1.Write([]byte("PART #local\r\n"))
		c2.Write([]byte("PART #local\r\n"))

		if !wfc(&s.Channels, 0) {
			t.Error("Could not destroy channel")
		}
	})
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

func Test100Clients(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	go s.Serve()

	for i := 0; i < 100; i++ {
		c, _ := net.Dial("tcp", ":6667")
		defer c.Close()
	}

	if !wfc(&s.Clients, 100) {
		t.Error(s.Clients.Len())
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
	for i := 0; i < 13; i++ {
		r.ReadBytes('\n')
	}

	return c, r
}

// wfc = wait for change
func wfc(s interface{}, eq interface{}) bool {
	c := make(chan bool)

	// start goroutine that continually checks pointer reference against
	// eq, and signals channel if true
	go func() {
		for {
			switch v := s.(type) {
			case *string:
				if *v == eq {
					c <- true
					return
				}
			case *util.List:
				if v.Len() == eq {
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
