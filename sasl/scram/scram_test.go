package scram

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"hash"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSCRAM(t *testing.T) {
	tests := []struct {
		// used for creating credential
		hash       func() hash.Hash
		pass, salt string
		iter       int

		sNonce string

		clientFirst, clientFinal, serverFinal string
	}{
		{ // from RFC 5802
			hash:        sha1.New,
			pass:        "pencil",
			salt:        decodeBase64("QSXCR+Q6sek8bf92"),
			iter:        4096,
			sNonce:      "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j",
			clientFirst: "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
			clientFinal: "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
			serverFinal: "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=",
		},
		{ // from RFC 7677
			hash:        sha256.New,
			pass:        "pencil",
			salt:        decodeBase64("W22ZaJ0SNY7soEsUEjb6gQ=="),
			iter:        4096,
			sNonce:      "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
			clientFirst: "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
			clientFinal: "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
			serverFinal: "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
		},
	}

	DB, err := initTable()
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range tests {
		cred := NewCredential(v.hash, "user", v.pass, v.salt, v.iter)
		DB.Exec("INSERT INTO sasl_scram VALUES(?, ?, ?, ?, ?)", cred.Username, cred.ServerKey, cred.StoredKey, cred.Salt, cred.Iteration)

		s := New(DB, v.hash)
		s.ParseClientFirst(v.clientFirst)
		s.nonce = v.sNonce

		s.GenServerFirst()
		s.ParseClientFinal(v.clientFinal)
		serverFinal, err := s.GenServerFinal()
		if err != nil {
			t.Error(err)
		}

		if v.serverFinal != string(serverFinal) {
			t.Error("something went wrong")
		}

		DB.Exec("DELETE FROM sasl_scram")
	}
}

func TestSCRAMLookup(t *testing.T) {
	DB, err := initTable()
	if err != nil {
		t.Fatal(err)
	}

	c := NewCredential(sha1.New, "username", "pass", "salt", 100)
	DB.Exec("INSERT INTO sasl_scram VALUES(?, ?, ?, ?, ?)", c.Username, c.ServerKey, c.StoredKey, c.Salt, c.Iteration)

	s := &Scram{db: DB}

	stored, err := s.lookup("username")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(c.StoredKey, stored.StoredKey) {
		t.Error("retrieved incorrect record")
	}
}

func initTable() (*sql.DB, error) {
	DB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}

	DB.Exec(`CREATE TABLE IF NOT EXISTS sasl_scram(
			username TEXT,
			serverKey BLOB,
			storedKey BLOB,
			salt BLOB,
			iterations INTEGER,
			PRIMARY KEY(username)
		);`)

	return DB, nil
}

func decodeBase64(s string) string {
	decoded := make([]byte, base64.StdEncoding.Strict().DecodedLen(len(s)))
	n, _ := base64.StdEncoding.Strict().Decode(decoded, []byte(s))
	return string(decoded[:n])
}
