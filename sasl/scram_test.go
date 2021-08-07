package sasl

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"testing"
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

	for _, v := range tests {
		cred := NewCredential(v.hash, "", v.pass, v.salt, v.iter)

		s := SCRAM(cred, v.hash)
		s.ParseClientFirst(v.clientFirst)
		s.nonce = v.sNonce

		s.GenServerFirst()
		s.ParseClientFinal(v.clientFinal)
		serverFinal, err := s.GenServerFinal()
		if err != nil {
			t.Error(err)
		}

		if v.serverFinal != serverFinal {
			t.Error("something went wrong")
		}
	}
}

func decodeBase64(s string) string {
	decoded := make([]byte, base64.StdEncoding.Strict().DecodedLen(len(s)))
	n, _ := base64.StdEncoding.Strict().Decode(decoded, []byte(s))
	return string(decoded[:n])
}
