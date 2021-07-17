package sasl

import (
	"bytes"
	"testing"
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
