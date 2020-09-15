package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/mitchr/gossip/client"
)

func main() {
	l, err := net.Listen("tcp", ":6667")
	if err != nil {
		fmt.Println("could not create server on :6667")
		log.Fatal(err)
	}

	defer l.Close()

	clients := &client.List{}
	for {
		// wait for a connection to the server
		// (block until one is received)
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("accepted connection")

		go func(c net.Conn) {
			// create entry for user
			u := client.New(c.RemoteAddr(), c)
			clients.Add(u)

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
				msgBuf, err := reader.ReadBytes('\n')

				if err != nil {
					if err == io.EOF {
						// client has closed connection, so we need to remove them from the user list
						u.Close()
						clients.Remove(u)
						return
					} else if operr, ok := err.(*net.OpError); ok {
						// there was some kind of network error
						u.Close()
						clients.Remove(u)
						fmt.Println(operr)
						return

					} else {
						// not sure what happened!
						u.Close()
						clients.Remove(u)
						fmt.Println(err)
						return
					}
				}
				// write to server
				// should probably also store in a log of some kind
				// fmt.Println(string(msgBuf))
				// write to client
				// conn.Write(msgBuf)

				err = Parse(msgBuf, u)
				if err != nil {
					if err == io.EOF {
						u.Close()
						clients.Remove(u)
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
		}(conn)
	}
}
