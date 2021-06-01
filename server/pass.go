package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
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
		return nil, errors.New("password do not match")
	}

	return bcrypt.GenerateFromPassword(p1, bcrypt.DefaultCost)
}

// Sets the server's password in its config file
func SetPass(path string) error {
	pass, err := getPassFromTerm()
	if err != nil {
		return err
	}

	c, err := loadConfig(path)
	if err != nil {
		return err
	}
	c.Password = string(pass)
	out, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, out, 0664)
}

// Adds an operator to the server's config file
func AddOp(path string) error {
	var user string
	fmt.Print("Username: ")
	fmt.Scanln(&user)

	pass, err := getPassFromTerm()
	if err != nil {
		return err
	}

	c, err := loadConfig(path)
	if err != nil {
		return err
	}

	c.Ops[user] = string(pass)
	out, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, out, 0664)
}
