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

	conn, err := net.Dial("tcp", ":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	t.Run("AcceptClient", func(t *testing.T) {
		// start new goroutine that continually checks the client field for any changes in length
		ch := make(chan bool)
		go func() {
			for {
				if len(s.Clients) != 0 {
					ch <- true
					return
				}
			}
		}()

		// if client was not accepted, fail all subtests
		if !waitForChange(ch) {
			t.Fatal("No client connection made")
		}

		// grab client from server
		c := s.Clients.Get(0).(*client.Client)

		t.Run("NICK", func(t *testing.T) {
			n, err := conn.Write([]byte("NICK alice\r\n"))
			if n <= 0 || err != nil {
				t.Error(err)
			}

			ch := make(chan bool)
			go func() {
				for {
					if c.Nick != "" {
						ch <- true
					}
				}
			}()

			if !waitForChange(ch) {
				t.Error("Nick not registered")
			} else if c.Nick != "alice" {
				t.Errorf("Nick registered incorrectly. Got %s\n", c.Nick)
			}
		})

		t.Run("USER", func(t *testing.T) {
			n, err := conn.Write([]byte("USER alice 0 * :Alice Smith\r\n"))
			if n <= 0 || err != nil {
				t.Error(err)
			}

			ch := make(chan bool)
			go func() {
				for {
					if c.User != "" {
						ch <- true
					}
				}
			}()

			if !waitForChange(ch) {
				t.Error("User not registered")
			} else if c.User != "alice" || c.Realname != "Alice Smith" {
				t.Errorf("User registered incorrectly. Got %s\n", c.User)
			}
		})

	t.Run("RegisterClient", func(t *testing.T) {
			if !c.Registered {
			t.Fatal("Client not registered")
		}

		r := bufio.NewReader(conn)
		t.Run("RSP_WELCOME", func(t *testing.T) {
			welcome, err := r.ReadBytes('\n')
			if err != nil {
				t.Error(err)
			}
			fmt.Println(string(welcome))
		})

		t.Run("RSP_YOURHOST", func(t *testing.T) {
			host, err := r.ReadBytes('\n')
			if err != nil {
				t.Error(err)
			}
			fmt.Println(string(host))
		})
	})
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
