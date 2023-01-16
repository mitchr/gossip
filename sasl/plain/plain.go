// Implementation of SASL PLAIN (RFC 4616)
package plain

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"

	"github.com/mitchr/gossip/sasl"
	"golang.org/x/crypto/bcrypt"
)

type Credential struct {
	Username string
	Pass     []byte
}

// A plain credential stores the bcrypted sha256 hash of pass
// https://security.stackexchange.com/questions/39849/does-bcrypt-have-a-maximum-password-length/184090#184090
func NewCredential(username string, pass string) *Credential {
	h := sha256.Sum256([]byte(pass))

	b, _ := bcrypt.GenerateFromPassword(h[:], bcrypt.DefaultCost)
	return &Credential{username, b}
}

func (c *Credential) Check(username string, pass []byte) bool {
	h := sha256.Sum256([]byte(pass))

	success := bcrypt.CompareHashAndPassword(c.Pass, h[:])
	return c.Username == username && success == nil
}

type Plain struct {
	authzid, authcid, pass []byte
	db                     *sql.DB
}

func New(db *sql.DB) *Plain { return &Plain{db: db} }

func (p *Plain) Authn() string { return string(p.authcid) }

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

	return nil, nil
}

func (p *Plain) lookup(username string) (*Credential, error) {
	c := &Credential{}
	row := p.db.QueryRow("SELECT username, pass FROM sasl_plain WHERE username = ?", username)
	err := row.Scan(&c.Username, &c.Pass)
	return c, err
}
