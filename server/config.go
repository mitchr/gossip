package server

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
)

type Config struct {
	// path to the underlying config file; used for rehashing
	path  string
	Debug bool `json:"-"`

	// The name of the network associated with the server
	Network string `json:"network"`

	// The name of this server
	Name     string `json:"name"`
	Password []byte `json:"password"`

	Port string `json:"port"`
	TLS  struct {
		*tls.Config `json:"-"`

		Enabled bool   `json:"enabled"`
		Port    string `json:"port"`

		// A path to the server's public key
		Pubkey string `json:"pubkey"`

		// A path to the server's private key
		Privkey string `json:"privkey"`
	} `json:"tls"`

	// A path to a file containg the server's message of the day. A MOTD
	// is divided when encountering a newline. If a line is too long, it
	// may run over the 512 byte message limit.
	MOTD string `json:"motd"`
	motd []string

	// A map where operator names are the keys and pass is the value
	Ops map[string][]byte `json:"ops"`
}

// Unmarshal's the server's config file
func loadConfig(file string) (*Config, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	c := Config{path: file}
	err = json.Unmarshal(b, &c)
	if err != nil {
		return nil, err
	}

	// convert []byte back from base64
	base64.StdEncoding.Decode(c.Password, c.Password)
	for k := range c.Ops {
		base64.StdEncoding.Decode(c.Ops[k], c.Ops[k])
	}

	return &c, err
}

// NewConfig reads the file at path into a Config.
func NewConfig(path string) (*Config, error) {
	c, err := loadConfig(path)
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

		c.TLS.Config = &tls.Config{ClientAuth: tls.RequestClientCert, Certificates: []tls.Certificate{cert}}
	}

	if c.MOTD != "" {
		m, err := ioutil.ReadFile(c.MOTD)
		if err != nil {
			return nil, err
		}
		c.motd = strings.Split(string(m), "\n")
	}
	return c, nil
}
