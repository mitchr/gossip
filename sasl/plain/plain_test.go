package plain

import (
	"bytes"
	"database/sql"
	"reflect"
	"testing"

	_ "modernc.org/sqlite"
)

func TestPLAIN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input                  []byte
		authzid, authcid, pass []byte
	}{
		{[]byte("\000tim\000tanstaaftanstaaf"), nil, []byte("tim"), []byte("tanstaaftanstaaf")},
		{[]byte("Ursel\000Kurt\000xipj3plmq"), []byte("Ursel"), []byte("Kurt"), []byte("xipj3plmq")},
	}

	db, err := initTable()
	if err != nil {
		t.Fatal(err)
	}

	p := New(db)

	for _, v := range tests {
		p.Next(v.input)

		if bytes.Equal(p.authzid, v.authcid) && bytes.Equal(p.authcid, v.authcid) && bytes.Equal(p.pass, v.pass) {
			t.Error("parsed incorrectly")
		}
	}
}

func TestLookup(t *testing.T) {
	t.Parallel()

	db, err := initTable()
	if err != nil {
		t.Fatal(err)
	}

	c := NewCredential("username", "pass")
	db.Exec("INSERT INTO sasl_plain VALUES(?, ?)", c.Username, c.Pass)

	p := New(db)
	stored, _ := p.lookup("username")
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
