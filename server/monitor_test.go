package server

import (
	"fmt"
	"testing"
)

func TestMONITOR(t *testing.T) {
	s, err := New(generateConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice")
	defer c.Close()

	t.Run("TestMissingParam", func(t *testing.T) {
		c.Write([]byte("MONITOR\r\nMONITOR +\r\nMONITOR -\r\n"))
		resp1, _ := r.ReadBytes('\n')
		resp2, _ := r.ReadBytes('\n')
		resp3, _ := r.ReadBytes('\n')
		assertResponse(resp1, fmt.Sprintf(ERR_NEEDMOREPARAMS, s.Name, "alice", "MONITOR"), t)
		assertResponse(resp2, fmt.Sprintf(ERR_NEEDMOREPARAMS, s.Name, "alice", "MONITOR"), t)
		assertResponse(resp3, fmt.Sprintf(ERR_NEEDMOREPARAMS, s.Name, "alice", "MONITOR"), t)
	})

	on, _ := connectAndRegister("online")
	defer on.Close()

	t.Run("TestMONITOR+", func(t *testing.T) {
		c.Write([]byte("MONITOR + online\r\n"))
		monline, _ := r.ReadBytes('\n')

		assertResponse(monline, fmt.Sprintf(RPL_MONONLINE, s.Name, "alice", "online!online@localhost"), t)
	})

	t.Run("TestMONITORL", func(t *testing.T) {
		c.Write([]byte("MONITOR L\r\n"))
		monlist, _ := r.ReadBytes('\n')
		monend, _ := r.ReadBytes('\n')

		assertResponse(monlist, fmt.Sprintf(RPL_MONLIST, s.Name, "alice", "online"), t)
		assertResponse(monend, fmt.Sprintf(RPL_ENDOFMONLIST, s.Name, "alice"), t)
	})

	t.Run("TestMONITOR+offline", func(t *testing.T) {
		c.Write([]byte("MONITOR + offline\r\n"))
		moffline, _ := r.ReadBytes('\n')
		assertResponse(moffline, fmt.Sprintf(RPL_MONOFFLINE, s.Name, "alice", "offline"), t)
	})

	t.Run("TestMONITORS", func(t *testing.T) {
		c.Write([]byte("MONITOR S\r\n"))
		monline, _ := r.ReadBytes('\n')
		moffline, _ := r.ReadBytes('\n')
		assertResponse(monline, fmt.Sprintf(RPL_MONONLINE, s.Name, "alice", "online!online@localhost"), t)
		assertResponse(moffline, fmt.Sprintf(RPL_MONOFFLINE, s.Name, "alice", "offline"), t)
	})

	off, r2 := connectAndRegister("offline")
	t.Run("TestNotifyOn", func(t *testing.T) {
		onNotif, _ := r.ReadBytes('\n')
		assertResponse(onNotif, fmt.Sprintf(RPL_MONONLINE, s.Name, "alice", "offline!offline@localhost"), t)
	})

	t.Run("TestNotifyOff", func(t *testing.T) {
		off.Close()
		r2.ReadBytes('\n')
		offNotif, _ := r.ReadBytes('\n')
		assertResponse(offNotif, fmt.Sprintf(RPL_MONOFFLINE, s.Name, "alice", "offline"), t)
	})

	t.Run("TestMONITOR-", func(t *testing.T) {
		c.Write([]byte("MONITOR - online\r\nMONITOR L\r\n"))
		monlist, _ := r.ReadBytes('\n')
		monend, _ := r.ReadBytes('\n')
		assertResponse(monlist, fmt.Sprintf(RPL_MONLIST, s.Name, "alice", "offline"), t)
		assertResponse(monend, fmt.Sprintf(RPL_ENDOFMONLIST, s.Name, "alice"), t)
	})

	t.Run("TestMONITORC", func(t *testing.T) {
		c.Write([]byte("MONITOR C\r\nMONITOR L\r\n"))
		monend, _ := r.ReadBytes('\n')
		assertResponse(monend, fmt.Sprintf(RPL_ENDOFMONLIST, s.Name, "alice"), t)
	})
}
