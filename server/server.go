package server

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/mitchr/gossip/client"
)

type Server struct {
	Listener net.Listener
	Clients  *client.List
	Created  time.Time
}

func New(port string) (*Server, error) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		return nil, err
	}
	return &Server{l, &client.List{}, time.Now()}, nil
}

// start server in new goroutine: go s.Start()
func (s *Server) Start() {
	defer s.Listener.Close()

	for {
		// wait for a connection to the server
		// (block until one is received)
		conn, err := s.Listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Println("accepted connection")

		// each client gets own goroutine for handling
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(c net.Conn) {
	// create entry for user
	u := client.New(c)
	s.Clients.Add(u)

	// when a client is added, the registrationg process must be attempted

	// go func(c *client.Client) {
	// 	for {
	// 		select {
	// 		case <-c.PING(l.Addr()):
	// 			fmt.Println("received PONG!")
	// 		case <-time.After(5 * time.Second):
	// 			fmt.Println("client missed PONG")
	// 		}
	// 	}
	// }(u)

	// fmt.Println(c.LocalAddr().Network(), c.LocalAddr().String())
	// fmt.Println(c.RemoteAddr().Network(), c.RemoteAddr().String())

	reader := bufio.NewReader(c)
	for {
		// read until we encounter a newline
		// really we should have \r\n, but we allow the parser to check that \r exists
		// also this removes the 512 byte message length limit, so we should consider if this is a meaningful regression
		// client could send so much data that the server crashes?
		msgBuf, err := reader.ReadBytes('\n')

		if err != nil {
			if err == io.EOF {
				// client has closed connection, so we need to remove them from the user list
				u.Close()
				s.Clients.Remove(u)
				return
			} else if operr, ok := err.(*net.OpError); ok {
				// there was some kind of network error
				u.Close()
				s.Clients.Remove(u)
				fmt.Println(operr)
				return

			} else {
				// not sure what happened!
				u.Close()
				s.Clients.Remove(u)
				fmt.Println(err)
				return
			}
		}
		// write to server
		// should probably also store in a log of some kind
		// fmt.Println(string(msgBuf))
		// wris.te to client
		// conn.Write(msgBuf)

		err = s.Parse(msgBuf, u)
		if err != nil {
			if err == io.EOF {
				u.Close()
				s.Clients.Remove(u)
				return
			} else {
				u.Write([]byte(fmt.Sprintln(err)))
			}
		}

		// err = u.Ping(l.Addr())
		// if err != nil {
		// 	fmt.Println(err)
		// }

		// write message to all clients who are connected
		// for i := 0; i < clients.Len(); i++ {
		// 	clients.Get(i).Write(msgBuf)
		// }
	}
}
