package external

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func initTable() (*sql.DB, error) {
	DB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}

	DB.Exec(`CREATE TABLE IF NOT EXISTS sasl_external(
		username TEXT,
		clientCert BLOB,
		PRIMARY KEY(username)
	);`)

	return DB, nil
}

func TestCredential(t *testing.T) {
	serverCert := generateCert()
	clientCert := generateCert()

	l, _ := tls.Listen("tcp", ":7070", &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequestClientCert})
	defer l.Close()

	go func() {
		_, err := tls.Dial("tcp", ":7070", &tls.Config{Certificates: []tls.Certificate{clientCert}, InsecureSkipVerify: true})
		if err != nil {
			fmt.Println(err)
		}
	}()

	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// client may not have written or read anything yet, so we need to force the handshake
	if !c.(*tls.Conn).ConnectionState().HandshakeComplete {
		err = c.(*tls.Conn).Handshake()
		if err != nil {
			t.Fatal(err)
		}
	}

	cred, err := NewCredential("alice", c)
	if err != nil {
		t.Fatal(err)
	}

	if !cred.Check("alice", c) {
		t.Fatal("Credential.Check failed")
	}
}

func TestExternal(t *testing.T) {
	serverCert := generateCert()
	clientCert := generateCert()
	// certPool, _ := x509.SystemCertPool()

	l, _ := tls.Listen("tcp", ":7070", &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequestClientCert})
	defer l.Close()

	go func() {
		_, err := tls.Dial("tcp", ":7070", &tls.Config{Certificates: []tls.Certificate{clientCert}, InsecureSkipVerify: true})
		if err != nil {
			fmt.Println(err)
		}
	}()

	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// client may not have written or read anything yet, so we need to force the handshake
	if !c.(*tls.Conn).ConnectionState().HandshakeComplete {
		err = c.(*tls.Conn).Handshake()
		if err != nil {
			t.Fatal(err)
		}
	}

	db, err := initTable()
	if err != nil {
		t.Fatal(err)
	}

	cred, err := NewCredential("alice", c)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec("INSERT INTO sasl_exec VALUES(?, ?)", cred.username, cred.cert)

	if !cred.Check("alice", c) {
		t.Error("check failed")
	}
}

func generateCert() tls.Certificate {
	sNum, _ := rand.Int(rand.Reader, big.NewInt(128))
	template := x509.Certificate{
		SerialNumber: sNum,
		DNSNames:     []string{"gossip"},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute * 1),
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)

	certPem := new(bytes.Buffer)
	keyPem := new(bytes.Buffer)
	pem.Encode(certPem, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	pem.Encode(keyPem, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	cert, _ := tls.X509KeyPair(certPem.Bytes(), keyPem.Bytes())
	return cert
}
