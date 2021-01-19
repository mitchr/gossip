package server

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestServer(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Error(err)
	}

	// start server in background goroutine
	go s.Start()

	conn, err := net.Dial("tcp", ":6667")
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	t.Run("AcceptClient", func(t *testing.T) {
		// start new goroutine that continually checks the client field for any changes in length
		ch := make(chan bool)
		go func() {
			for {
				if s.Clients.Len != 0 {
					ch <- true
					return
				}
			}
		}()

		// if client was not accepted, fail all subtests
		if !waitForChange(ch) {
			t.Fatal("No client connection made")
		}

		t.Run("NICK", func(t *testing.T) {
			n, err := conn.Write([]byte("NICK alice\r\n"))
			if n <= 0 || err != nil {
				t.Error(err)
			}
			client := s.Clients.Get(0)

			ch := make(chan bool)
			go func() {
				for {
					if client.Nick != "" {
						ch <- true
					}
				}
			}()

			if !waitForChange(ch) {
				t.Error("Nick not registered")
			} else if client.Nick != "alice" {
				t.Errorf("Nick registered incorrectly. Got %s\n", client.Nick)
			}
		})

		t.Run("USER", func(t *testing.T) {
			n, err := conn.Write([]byte("USER alice 0 * :Alice Smith\r\n"))
			if n <= 0 || err != nil {
				t.Error(err)
			}
			client := s.Clients.Get(0)

			ch := make(chan bool)
			go func() {
				for {
					if client.User != "" {
						ch <- true
					}
				}
			}()

			if !waitForChange(ch) {
				t.Error("User not registered")
			} else if client.User != "alice" || client.Realname != "Alice Smith" {
				t.Errorf("User registered incorrectly. Got %s\n", client.User)
			}
		})
	})

	t.Run("RegisterClient", func(t *testing.T) {
		client := s.Clients.Get(0)

		if !client.Registered {
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
