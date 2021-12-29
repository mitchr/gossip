package server

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

type Config struct {
	// reference to underlying source of config data; used for rehashing
	configSource io.Reader
	Debug        bool `json:"-"`

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

		STS struct {
			// Enables strict transport security, which provides opportunistic
			// TLS client connection upgrades
			Enabled bool `json:"enabled"`

			// The port that clients should be told to connect to. This defaults
			// to TLS.Port if not set.
			Port string `json:"port"`

			// The time that is advertised to clients about how long they should
			// stay connected with TLS. This defaults to the difference between
			// the current time and the `NotAfter` property of the server's
			// certificate.
			Duration time.Duration `json:"duration"`

			// https://ircv3.net/specs/extensions/sts#the-preload-key
			// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security#preloading_strict_transport_security
			// Tell clients that this server should be included in STS preload
			// lists (promise that your server will always offer a secure
			// connection to clients)
			Preload bool `json:"preload"`
		} `json:"sts,omitempty"`
	} `json:"tls,omitempty"`

	// A path to a file containg the server's message of the day. A MOTD
	// is divided when encountering a newline. If a line is too long, it
	// may run over the 512 byte message limit.
	MOTD string `json:"motd"`
	motd []string

	// A map where operator names are the keys and pass is the value
	Ops map[string][]byte `json:"ops,omitempty"`
}

// Unmarshal's the server's config file
func loadConfig(r io.Reader) (*Config, error) {
	decoder := json.NewDecoder(r)

	c := &Config{configSource: r}
	err := decoder.Decode(c)
	if err != nil {
		return nil, err
	}

	// convert []byte back from base64
	base64.StdEncoding.Decode(c.Password, c.Password)
	for k := range c.Ops {
		base64.StdEncoding.Decode(c.Ops[k], c.Ops[k])
	}

	return c, nil
}

// NewConfig reads the file at path into a Config.
func NewConfig(r io.Reader) (*Config, error) {
	c, err := loadConfig(r)
	if err != nil {
		return nil, err
	}

	if c.TLS.Enabled {
		if c.TLS.Port == "" {
			return nil, errors.New("TLS.Port must be defined")
		}

		if c.TLS.STS.Port != "" {
			c.TLS.STS.Port = c.TLS.Port[1:]
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

func WriteConfigToPath(c *Config, path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "\t")
	return encoder.Encode(c)
}
