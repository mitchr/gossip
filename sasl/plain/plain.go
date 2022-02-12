// Implementation of SASL PLAIN (RFC 4616)
package plain

import (
	"bytes"
	"database/sql"
	"errors"

	"github.com/mitchr/gossip/sasl"
	"golang.org/x/crypto/bcrypt"
)

type Credential struct {
	Username string
	Pass     []byte
}

// A plain credential stores the bcrypt of the password
func NewCredential(username string, pass string) *Credential {
	b, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	return &Credential{username, b}
}

func (c *Credential) Check(username string, pass []byte) bool {
	success := bcrypt.CompareHashAndPassword(c.Pass, pass)
	return c.Username == username && success == nil
}

type Plain struct {
	authzid, authcid, pass []byte
	db                     *sql.DB
}

func New(db *sql.DB) *Plain { return &Plain{db: db} }

func (p *Plain) Next(b []byte) (challenge []byte, err error) {
	out := bytes.Split(b, []byte{0})
	if len(out) == 2 {
		p.authcid, p.pass = out[0], out[1]
	} else if len(out) == 3 {
		p.authzid, p.authcid, p.pass = out[0], out[1], out[2]
	} else {
		return nil, errors.New("missing param for PLAIN")
	}

	cred, err := p.lookup(string(p.authcid))
	if err != nil {
		return nil, sasl.ErrInvalidKey
	}

	if !cred.Check(string(p.authcid), p.pass) {
		return nil, sasl.ErrInvalidKey
	}

	return nil, sasl.ErrDone
}

func (p *Plain) lookup(username string) (*Credential, error) {
	c := &Credential{}
	row := p.db.QueryRow("SELECT * FROM sasl_plain WHERE username = ?", username)
	err := row.Scan(&c.Username, &c.Pass)
	return c, err
}
