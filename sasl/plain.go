package sasl

import (
	"bytes"
	"errors"
)

// Implementation of SASL PLAIN (RFC 4616)
func PLAIN(b []byte) (authzid, authcid, pass []byte, err error) {
	out := bytes.Split(b, []byte{0})
	if len(out) == 2 {
		authcid, pass = out[0], out[1]
	} else if len(out) == 3 {
		authzid, authcid, pass = out[0], out[1], out[2]
	} else {
		err = errors.New("missing param for PLAIN")
	}
	return
}
