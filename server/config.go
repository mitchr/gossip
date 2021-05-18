package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
)

type Config struct {
	// The name of the network associated with the server
	Network string `json:"network"`

	// The name of this server
	Name     string `json:"name"`
	Password string `json:"password"`

	Port string `json:"port"`
	TLS  struct {
		Enabled bool   `json:"enabled"`
		Port    string `json:"port"`

		// A path to the server's public key
		Pubkey string `json:"pubkey"`

		// A path to the server's private key
		Privkey string `json:"privkey"`

		conf *tls.Config
	} `json:"tls"`

	// A path to a file containg the server's message of the day. A MOTD
	// is divided when encountering a newline. If a line is too long, it
	// may run over the 512 byte message limit.
	MOTD string `json:"motd"`
	motd []string

	Ops []string `json:"ops"`
}

// NewConfig reads the file at path into a Config.
func NewConfig(path string) (*Config, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var c Config
	err = json.Unmarshal(b, &c)
	if err != nil {
		return nil, err
	}

	if c.TLS.Enabled {
		if c.TLS.Port == "" {
			return nil, errors.New("TLS.Port must be defined")
		}

		cert, err := tls.LoadX509KeyPair(c.TLS.Pubkey, c.TLS.Privkey)
		if err != nil {
			return nil, err
		}

		c.TLS.conf = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	if c.MOTD != "" {
		m, err := ioutil.ReadFile(c.MOTD)
		if err != nil {
			return nil, err
		}
		c.motd = strings.Split(string(m), "\n")
	}
	return &c, nil
}
