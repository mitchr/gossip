// Implementation of SASL EXTERNAL (RFC 4422)
package external

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/sasl"
)

type Credential struct {
	Username string
	Cert     []byte
}

// keeps the sha hash of the certificate (the fingerprint)
func NewCredential(username string, baseConn net.Conn) (*Credential, error) {
	conn, ok := baseConn.(*tls.Conn)
	if !ok { // not a tls connection
		return nil, errors.New("not connected over tls")
	}

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return nil, errors.New("client has no associated certificate")
	}

	sha := sha256.New()
	sha.Write(certs[0].Raw)
	fingerprint := sha.Sum(nil)

	return &Credential{username, fingerprint}, nil
}

func (c *Credential) Check(username string, fingerprint []byte) bool {
	return c.Username == username && (subtle.ConstantTimeCompare(c.Cert, fingerprint) == 1)
}

type External struct {
	db     *sql.DB
	client *client.Client
}

func New(db *sql.DB, client *client.Client) *External { return &External{db, client} }

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

	return nil, sasl.ErrDone
}

func (e *External) lookup(username string) (*Credential, error) {
	c := &Credential{}
	row := e.db.QueryRow("SELECT * FROM sasl_external WHERE username = ?", username)
	err := row.Scan(&c.Username, &c.Cert)
	return c, err
}
