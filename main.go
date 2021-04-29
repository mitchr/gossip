package main

import (
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/mitchr/gossip/server"
)

func main() {
	flag.Parse()

	c, err := server.NewConfig("./config.json")
	if err != nil {
		log.Fatalln(err)
	}

	s, err := server.New(c)
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
