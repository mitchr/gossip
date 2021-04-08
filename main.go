package main

import (
	"flag"
	"log"
	"os"
	"os/signal"

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

	// capture OS interrupt signal so that we can gracefully shutdown server
	interrupt := make(chan os.Signal)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		<-interrupt
		s.Close()
	}()

	s.Serve()
}
