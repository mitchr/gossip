package main

import (
	"flag"
	"log"

	"github.com/mitchr/gossip/server"
)

// default port of 8080
var port *string = flag.String("port", ":8080", "sets server port")

func main() {
	flag.Parse()

	s, err := server.New(*port)
	defer s.Close()

	if err != nil {
		log.Fatalln(err)
	}

	s.Start()
}
