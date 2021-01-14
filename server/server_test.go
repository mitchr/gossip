package server

import (
	"testing"
)

func TestNewServer(t *testing.T) {
	s, err := New(":8080")
	defer s.Close()

	if err != nil {
		t.Error(err)
	}
}

func TestStartServer(t *testing.T) {
	s, err := New(":8080")
	defer s.Close()

	if err != nil {
		t.Error(err)
	}
	go s.Start()
}
