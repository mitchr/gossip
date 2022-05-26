// Implementation of SCRAM (RFC 5802)
package scram

import (
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

type Scram struct {
	db   *sql.DB
	step int

	// gs2Header string
	nonce string
	proof []byte // sent from client

	// used for computing serverSignature
	clientFirstBare, serverFirst, clientFinalWithoutProof string

	// the cred associated with the requesting client
	cred *Credential

	// hash function (`H()` in RFC 5802)
	hash func() hash.Hash
}

func (s *Scram) Authn() string { return s.cred.Username }

func (s *Scram) Next(clientResponse []byte) (challenge []byte, err error) {
	// always increment step
	defer func() {
		s.step++
	}()

	switch s.step {
	case 0:
		err := s.ParseClientFirst(string(clientResponse))
		if err != nil {
			return nil, err
		}

		return s.GenServerFirst(), nil
	case 1:
		err := s.ParseClientFinal(string(clientResponse))
		if err != nil {
			return nil, err
		}

		return s.GenServerFinal()
	}

	return nil, nil
}

func New(db *sql.DB, h func() hash.Hash) *Scram { return &Scram{db: db, hash: h} }

func (s *Scram) ParseClientFirst(m string) error {
	attrs := strings.Split(m, ",")
	if len(attrs) < 4 {
		return errors.New("e=other-error")
	}

	// attrs[1] is unused as we do not take advantage of authzid

	// grab username from db
	cred, err := s.lookup(attrs[2][2:])
	if err != nil {
		return errors.New("e=unknown-user")
	}
	s.cred = cred

	// add arbitrary length nonce with size in [24, 32)
	nonceLength, _ := rand.Int(rand.Reader, big.NewInt(32-24))
	nonce := make([]byte, nonceLength.Int64()+24)
	rand.Read(nonce)
	s.nonce = attrs[3][2:] + base64.StdEncoding.EncodeToString(nonce)

	s.clientFirstBare = strings.Join(attrs[2:], ",")
	return nil
}

func (s *Scram) GenServerFirst() []byte {
	s.serverFirst = fmt.Sprintf("r=%s,s=%s,i=%d",
		s.nonce,
		base64.StdEncoding.EncodeToString(s.cred.Salt),
		s.cred.Iteration,
	)
	return []byte(s.serverFirst)
}

func (s *Scram) ParseClientFinal(m string) error {
	attrs := strings.Split(m, ",")
	if len(attrs) < 3 {
		return errors.New("e=other-error")
	}

	// attrs[0] is unused since we don't use channel binding
	nonce := attrs[1][2:]
	if nonce != s.nonce {
		return errors.New("e=other-error")
	}

	proof, err := base64.StdEncoding.DecodeString(attrs[2][2:])
	if err != nil {
		return errors.New("e=invalid-encoding")
	}
	s.proof = proof

	s.clientFinalWithoutProof = strings.Join(attrs[:2], ",")
	return nil
}

func (s *Scram) GenServerFinal() ([]byte, error) {
	authMsg := []byte(fmt.Sprintf("%s,%s,%s", s.clientFirstBare, s.serverFirst, s.clientFinalWithoutProof))

	mac := hmac.New(s.hash, s.cred.StoredKey)
	mac.Write(authMsg)
	clientSignature := mac.Sum(nil)

	clientKey := bytewiseXOR(clientSignature, s.proof)

	hash := s.hash()
	hash.Write(clientKey)
	storedKey := hash.Sum(nil)

	if !hmac.Equal(storedKey, s.cred.StoredKey) {
		return nil, errors.New("e=invalid-proof")
	}

	mac = hmac.New(s.hash, s.cred.ServerKey)
	mac.Write(authMsg)
	serverSignature := mac.Sum(nil)

	verifier := make([]byte, base64.StdEncoding.EncodedLen(len(serverSignature)))
	base64.StdEncoding.Encode(verifier, serverSignature)
	return append([]byte("v="), verifier...), nil
}

func bytewiseXOR(b1, b2 []byte) []byte {
	if len(b1) != len(b2) {
		return nil
	}

	x := make([]byte, len(b1))
	for i := range x {
		x[i] = b1[i] ^ b2[i]
	}
	return x
}
