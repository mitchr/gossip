package server

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mitchr/gossip/client"
)

func TestServer(t *testing.T) {
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

	ch := make(chan bool)
	go func() {
		for {
			if len(s.Clients) == 100 {
				ch <- true
			}
		}
	}()
	if !waitForChange(ch) {
		t.Error(len(s.Clients))
	}
}

// helper function that returns true if c returns a value before 500 miliseconds have elapsed
func waitForChange(c chan bool) bool {
	select {
	case <-c:
		return true
	case <-time.After(time.Millisecond * 500):
		return false
	}
}
