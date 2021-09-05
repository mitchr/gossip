// Implementation of SASL EXTERNAL (RFC 4422)
package external

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
)

type Credential struct {
	username string
	cert     []byte
}

// A plain credential stores the bcrypt of the password
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

func (c *Credential) Check(username string, baseConn net.Conn) bool {
	conn, ok := baseConn.(*tls.Conn)
	if !ok { // not a tls connection
		return false
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return false
	}

	sha := sha256.New()
	sha.Write(certs[0].Raw)
	fingerprint := sha.Sum(nil)

	return c.username == username && bytes.Equal(c.cert, fingerprint)
}

func Lookup(db *sql.DB, username string) (*Credential, error) {
	c := &Credential{}
	row := db.QueryRow("SELECT * FROM sasl_external WHERE username = ?", username)
	err := row.Scan(&c.username, &c.cert)
	return c, err
}
