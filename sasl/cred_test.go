package sasl

import (
	"crypto/sha1"
	"testing"
)

func TestCredential(t *testing.T) {
	c := NewCredential(sha1.New, "username", "pass", "salt", 100)

	if !c.Check("username", "pass") {
		t.Error("check failed")
	}
}
