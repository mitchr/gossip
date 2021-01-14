package server

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/mitchr/gossip/client"
)

type Server struct {
	listener net.Listener
	clients  *client.List
}

// should defer s.Close() after calling New()
func New(port string) (*Server, error) {
	l, err := net.Listen("tcp", port)
	if err != nil {
		return nil, err
	}
	return &Server{l, &client.List{}}, nil
}

// start server in new goroutine: go s.Start()
func (s *Server) Start() {
	for {
		// wait for a connection to the server
		// (block until one is received)
		conn, err := s.listener.Accept()
		if err != nil {
			log.Println(err)
		}
		log.Println("accepted connection")

		// each client gets own goroutine for handling
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(c net.Conn) {
	// used when sending RPL_CREATED 003
	// creationTime := time.Now()

	// create entry for user
	u := client.New(c, s.listener)
	s.clients.Add(u)

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
				s.clients.Remove(u)
				return
			} else if operr, ok := err.(*net.OpError); ok {
				// there was some kind of network error
				u.Close()
				s.clients.Remove(u)
				fmt.Println(operr)
				return

			} else {
				// not sure what happened!
				u.Close()
				s.clients.Remove(u)
				fmt.Println(err)
				return
			}
		}
		// write to server
		// should probably also store in a log of some kind
		// fmt.Println(string(msgBuf))
		// wris.te to client
		// conn.Write(msgBuf)

		err = Parse(msgBuf, u)
		if err != nil {
			if err == io.EOF {
				u.Close()
				s.clients.Remove(u)
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

func (s *Server) addClient(c *client.Client) {
	s.clients.Add(c)
}

func (s *Server) Close() {
	s.listener.Close()
}
