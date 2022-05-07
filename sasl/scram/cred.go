package scram

import (
	"crypto/hmac"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

type Credential struct {
	// stored hash so we can generated storedkey again
	hash func() hash.Hash

	Username string

	ServerKey []byte // HMAC(SaltedPassword, "Server Key")
	StoredKey []byte // H(ClientKey)
	Salt      []byte
	Iteration int
}

var (
	serverHMACMsg = []byte("Server Key")
	clientHMACMsg = []byte("Client Key")
)

func NewCredential(hash func() hash.Hash, uname, pass string, salt []byte, iter int) *Credential {
	c := &Credential{hash: hash, Username: uname, Salt: salt, Iteration: iter}

	saltedPass := pbkdf2.Key([]byte(pass), salt, iter, hash().Size(), hash)

	mac := hmac.New(hash, saltedPass)
	mac.Write([]byte(serverHMACMsg))
	c.ServerKey = mac.Sum(nil)

	mac.Reset()
	mac.Write([]byte(clientHMACMsg))
	clientKey := mac.Sum(nil)

	h := hash()
	h.Write(clientKey)
	c.StoredKey = h.Sum(nil)

	return c
}

func (s *Scram) lookup(username string) (*Credential, error) {
	row := s.db.QueryRow("SELECT * FROM sasl_scram WHERE username = ?", username)

	c := &Credential{}
	err := row.Scan(&c.Username, &c.ServerKey, &c.StoredKey, &c.Salt, &c.Iteration)
	return c, err
}
