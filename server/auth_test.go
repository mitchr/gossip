package server

import (
	"testing"
)

func TestREGISTER(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	conn, r := connectAndRegister("alice", "Alice Smith")
	defer conn.Close()

	conn.Write([]byte("REGISTER PASS pass1\r\n"))
	resp, _ := r.ReadBytes('\n')

	assertResponse(resp, "NOTICE Registered\r\n", t)
}
