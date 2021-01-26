package server

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
)

type Server struct {
	Listener net.Listener
	Clients  *client.List
	Created  time.Time
	Channels []*channel.Channel
}

func New(port string) (*Server, error) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		return nil, err
	}
	return &Server{Listener: l, Clients: &client.List{}, Created: time.Now()}, nil
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
		u := client.New(conn)

		// each client gets own goroutine for handling
		go s.handleClient(u)
	}
}

func (s *Server) handleClient(c *client.Client) {
	// create entry for user
	s.Clients.Add(c)

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
			} else if operr, ok := err.(*net.OpError); ok {
				// there was some kind of network error
				fmt.Println(operr)
			} else {
				// not sure what happened!
				fmt.Println(err)
			}
			c.Close()
			s.Clients.Remove(c)
			return
		}
		// write to server
		// should probably also store in a log of some kind
		// fmt.Println(string(msgBuf))
		// wris.te to client
		// conn.Write(msgBuf)

		msg := parse(lex(msgBuf))
		if msg == nil {
			log.Println("message is nil; ignored")
		} else {
			s.executeMessage(msg, c)
		}

		// err = s.Parse(msgBuf, c)
		// if err != nil {
		// 	if err == io.EOF {
		// 		c.Close()
		// 		s.Clients.Remove(c)
		// 		return
		// 	} else {
		// 		c.Write(err)
		// 	}
		// }

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
