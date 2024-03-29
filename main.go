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
	confFile, err := os.Open(confPath)
	if err != nil {
		log.Fatalln(err)
	}

	c, err := server.NewConfig(confFile)
	if err != nil {
		log.Fatalln(err)
	}
	c.Debug = debug

	if sPass {
		err := c.SetPass()
		if err != nil {
			log.Fatalln(err)
		}
		err = server.WriteConfigToPath(c, confPath)
		if err != nil {
			log.Fatalln(err)
		}
		return
	}
	if oPass {
		err := c.AddOp()
		if err != nil {
			log.Fatalln(err)
		}
		err = server.WriteConfigToPath(c, confPath)
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

	go s.Serve()

	<-interrupt
	err = s.Close()
	if err != nil {
		log.Fatalln(err)
	}
}
