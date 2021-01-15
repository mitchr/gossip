package server

import (
	"testing"
)

func TestNewServer(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Error(err)
	}
	defer s.Listener.Close()
}

func TestStartServer(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Error(err)
	}
	defer s.Listener.Close()

	go s.Start()
}

func TestStartServer(t *testing.T) {
	s, err := New(":6667")
	defer s.Listener.Close()

	if err != nil {
		t.Error(err)
	}
	go s.Start()
}
