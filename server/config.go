package server

import (
	"encoding/json"
	"io/ioutil"
)

type Config struct {
	Name     string `json:"name"`
	Password string `json:"password"`

	Port string `json:"port"`
	Tls  struct {
		Port    string `json:"port"`
		Pubkey  string `json:"pubkey"`
		Privkey string `json:"privkey"`
	} `json:"tls"`

	MOTD string   `json:"motd"`
	Ops  []string `json:"ops"`
}

func NewConfig(path string) (*Config, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var c Config
	json.Unmarshal(b, &c)
	return &c, nil
}
