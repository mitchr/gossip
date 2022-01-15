package server

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func getPassFromTerm() ([]byte, error) {
	fmt.Print("Password: ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}

	fmt.Print("\nReenter password: ")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Println()

	if !bytes.Equal(p1, p2) {
		return nil, errors.New("passwords do not match")
	}

	return bcrypt.GenerateFromPassword(p1, bcrypt.DefaultCost)
}

// Sets the server's password in its config file
func (c *Config) SetPass() error {
	pass, err := getPassFromTerm()
	if err != nil {
		return err
	}

	c.Password = pass
	return nil
}

// Adds an operator to the server's config file
func (c *Config) AddOp() error {
	var user string
	fmt.Print("Username: ")
	fmt.Scanln(&user)

	pass, err := getPassFromTerm()
	if err != nil {
		return err
	}

	if c.Ops == nil {
		c.Ops = make(map[string][]byte)
	}
	c.Ops[user] = pass

	return nil
}
