package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
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
	} `json:"tls"`

	MOTD string   `json:"motd"`
	Ops  []string `json:"ops"`
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
	return &c, nil
}

func (c *Config) TLSConfig() (*tls.Config, error) {
	if c.TLS.Port == "" {
		return nil, errors.New("TLS.Port must be defined")
	}

	if c.TLS.Pubkey == "" || c.TLS.Privkey == "" {
		return nil, errors.New("TLS.Pubkey and TLS.Privkey must be defined to use TLS")
	}

	cert, err := tls.LoadX509KeyPair(c.TLS.Pubkey, c.TLS.Privkey)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}
