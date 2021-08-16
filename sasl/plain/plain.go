// Implementation of SASL PLAIN (RFC 4616)
package sasl

import (
	"bytes"
	"database/sql"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type Credential struct {
	username string
	pass     []byte
}

// A plain credential stores the bcrypt of the password
func NewCredential(username string, pass string) *Credential {
	b, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	return &Credential{username, b}
}

func (c *Credential) Check(username string, pass []byte) bool {
	success := bcrypt.CompareHashAndPassword(c.pass, pass)
	return c.username == username && success == nil
}

func Lookup(db *sql.DB, username string) (*Credential, error) {
	c := &Credential{}
	row := db.QueryRow("SELECT * FROM sasl_plain WHERE username = ?", username)
	err := row.Scan(&c.username, &c.pass)
	return c, err
}

func PLAIN(b []byte) (authzid, authcid, pass []byte, err error) {
	out := bytes.Split(b, []byte{0})
	if len(out) == 2 {
		authcid, pass = out[0], out[1]
	} else if len(out) == 3 {
		authzid, authcid, pass = out[0], out[1], out[2]
	} else {
		err = errors.New("missing param for PLAIN")
	}
	return
}
