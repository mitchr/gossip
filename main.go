package main

import (
	"flag"
	"log"

	"github.com/mitchr/gossip/server"
)

// default port of 8080
var port *string = flag.String("port", ":6667", "sets server port")

func main() {
	flag.Parse()

	s, err := server.New(*port)
	if err != nil {
		log.Fatalln(err)
	}

	defer s.Close()
}
