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

func (c *Credential) Check(username string, conn *tls.Conn) bool {
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return false
	}

	sha := sha256.New()
	sha.Write(certs[0].Raw)
	fingerprint := sha.Sum(nil)

	return c.Username == username && (subtle.ConstantTimeCompare(c.Cert, fingerprint) == 1)
}

type External struct {
	db     *sql.DB
	client *client.Client
}

func NewExternal(db *sql.DB, client *client.Client) *External { return &External{db, client} }

func (e *External) Next(clientResponse []byte) (challenge []byte, err error) {
	// client is not connected over TLS, so we should not move forward checking for cert
	if !e.client.IsSecure() {
		return nil, sasl.ErrSaslFail
	}

	cred, err := e.lookup(e.client.Nick)
	if err != nil {
		return nil, sasl.ErrSaslFail
	}

	if !cred.Check(e.client.Nick, e.client.Conn.(*tls.Conn)) {
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
