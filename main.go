package main

import (
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/mitchr/gossip/server"
)

var (
	sPass    bool
	oPass    bool
	debug    bool
	confPath string
)

func init() {
	flag.BoolVar(&sPass, "s", false, "sets server password")
	flag.BoolVar(&oPass, "o", false, "add a server operator (username and pass)")
	flag.BoolVar(&debug, "d", false, "print incoming messages to stdout")
	flag.StringVar(&confPath, "conf", "config.json", "path to the config file")
	flag.Parse()
}

func main() {
	c, err := server.NewConfig(confPath)
	if err != nil {
		log.Fatalln(err)
	}
	c.Debug = debug

	if sPass {
		err := server.SetPass(c)
		if err != nil {
			log.Fatalln(err)
		}
		return
	}
	if oPass {
		err := server.AddOp(c)
		if err != nil {
			log.Fatalln(err)
		}
		return
	}

	s, err := server.New(c)
	if err != nil {
		log.Fatalln(err)
	}

	// capture OS interrupt signal so that we can gracefully shutdown server
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		<-interrupt
		s.Close()
	}()

	s.Serve()
}
