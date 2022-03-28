// Implementation of SASL EXTERNAL (RFC 4422)
package external

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/sasl"
)

type Credential struct {
	Username string
	Cert     []byte
}

// keeps the sha hash of the certificate (the fingerprint)
func NewCredential(username string, cert []byte) *Credential {
	sha := sha256.New()
	sha.Write(cert)
	fingerprint := sha.Sum(nil)

	return &Credential{username, fingerprint}
}

func (c *Credential) Check(username string, fingerprint []byte) bool {
	return c.Username == username && (subtle.ConstantTimeCompare(c.Cert, fingerprint) == 1)
}

type External struct {
	db     *sql.DB
	client *client.Client
}

func New(db *sql.DB, client *client.Client) *External { return &External{db, client} }

func (e *External) Authn() string { return e.client.Nick }

func (e *External) Next([]byte) (challenge []byte, err error) {
	// grab client cert if it exists
	certfp, err := e.client.CertificateSha()
	if err != nil {
		return nil, sasl.ErrSaslFail
	}

	cred, err := e.lookup(e.client.Nick)
	if err != nil {
		return nil, sasl.ErrSaslFail
	}

	if !cred.Check(e.client.Nick, certfp) {
		return nil, sasl.ErrInvalidKey
	}

	return nil, nil
}

func (e *External) lookup(username string) (*Credential, error) {
	c := &Credential{}
	row := e.db.QueryRow("SELECT * FROM sasl_external WHERE username = ?", username)
	err := row.Scan(&c.Username, &c.Cert)
	return c, err
}
