package server

import (
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
		assertResponse(resp1, prepMessage(ERR_NEEDMOREPARAMS, s.Name, "alice", "MONITOR").String(), t)
		assertResponse(resp2, prepMessage(ERR_NEEDMOREPARAMS, s.Name, "alice", "MONITOR").String(), t)
		assertResponse(resp3, prepMessage(ERR_NEEDMOREPARAMS, s.Name, "alice", "MONITOR").String(), t)
	})

	on, _ := connectAndRegister("online")
	defer on.Close()

	t.Run("TestMONITOR+", func(t *testing.T) {
		c.Write([]byte("MONITOR + online\r\n"))
		monline, _ := r.ReadBytes('\n')

		assertResponse(monline, prepMessage(RPL_MONONLINE, s.Name, "alice", "online!online@localhost").String(), t)
	})

	t.Run("TestMONITORL", func(t *testing.T) {
		c.Write([]byte("MONITOR L\r\n"))
		monlist, _ := r.ReadBytes('\n')
		monend, _ := r.ReadBytes('\n')

		assertResponse(monlist, prepMessage(RPL_MONLIST, s.Name, "alice", "online").String(), t)
		assertResponse(monend, prepMessage(RPL_ENDOFMONLIST, s.Name, "alice").String(), t)
	})

	t.Run("TestMONITOR+offline", func(t *testing.T) {
		c.Write([]byte("MONITOR + offline\r\n"))
		moffline, _ := r.ReadBytes('\n')
		assertResponse(moffline, prepMessage(RPL_MONOFFLINE, s.Name, "alice", "offline").String(), t)
	})

	t.Run("TestMONITORS", func(t *testing.T) {
		c.Write([]byte("MONITOR S\r\n"))
		monline, _ := r.ReadBytes('\n')
		moffline, _ := r.ReadBytes('\n')
		assertResponse(monline, prepMessage(RPL_MONONLINE, s.Name, "alice", "online!online@localhost").String(), t)
		assertResponse(moffline, prepMessage(RPL_MONOFFLINE, s.Name, "alice", "offline").String(), t)
	})

	off, r2 := connectAndRegister("offline")
	t.Run("TestNotifyOn", func(t *testing.T) {
		onNotif, _ := r.ReadBytes('\n')
		assertResponse(onNotif, prepMessage(RPL_MONONLINE, s.Name, "*", "offline!offline@localhost").String(), t)
	})

	t.Run("TestNotifyOff", func(t *testing.T) {
		off.Close()
		r2.ReadBytes('\n')
		offNotif, _ := r.ReadBytes('\n')
		assertResponse(offNotif, prepMessage(RPL_MONOFFLINE, s.Name, "*", "offline").String(), t)
	})

	t.Run("TestMONITOR-", func(t *testing.T) {
		c.Write([]byte("MONITOR - online\r\nMONITOR L\r\n"))
		monlist, _ := r.ReadBytes('\n')
		monend, _ := r.ReadBytes('\n')
		assertResponse(monlist, prepMessage(RPL_MONLIST, s.Name, "alice", "offline").String(), t)
		assertResponse(monend, prepMessage(RPL_ENDOFMONLIST, s.Name, "alice").String(), t)
	})

	t.Run("TestMONITORC", func(t *testing.T) {
		c.Write([]byte("MONITOR C\r\nMONITOR L\r\n"))
		monend, _ := r.ReadBytes('\n')
		assertResponse(monend, prepMessage(RPL_ENDOFMONLIST, s.Name, "alice").String(), t)
	})
}
