package sasl

import (
	"bytes"
	"database/sql"
	"reflect"
	"testing"

	_ "modernc.org/sqlite"
)

func TestPLAIN(t *testing.T) {
	tests := []struct {
		input                  []byte
		authzid, authcid, pass []byte
	}{
		{[]byte("\000tim\000tanstaaftanstaaf"), nil, []byte("tim"), []byte("tanstaaftanstaaf")},
		{[]byte("Ursel\000Kurt\000xipj3plmq"), []byte("Ursel"), []byte("Kurt"), []byte("xipj3plmq")},
	}

	for _, v := range tests {
		authzid, authcid, pass, err := PLAIN(v.input)
		if err != nil {
			t.Error(err)
		}

		if bytes.Equal(authzid, v.authcid) && bytes.Equal(authcid, v.authcid) && bytes.Equal(pass, v.pass) {
			t.Error("parsed incorrectly")
		}
	}
}

func TestLookup(t *testing.T) {
	db, err := initTable()
	if err != nil {
		t.Fatal(err)
	}

	c := NewCredential("username", "pass")
	db.Exec("INSERT INTO sasl_plain VALUES(?, ?)", c.username, c.pass)

	p := &plain{db}
	stored, _ := p.Lookup("username")
	if !reflect.DeepEqual(c, stored) {
		t.Fail()
	}
}

func initTable() (*sql.DB, error) {
	DB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}

	DB.Exec(`CREATE TABLE IF NOT EXISTS sasl_plain(
		username TEXT,
		pass BLOB,
		PRIMARY KEY(username)
	);`)

	return DB, nil
}
