package server

import (
	"strings"
	"sync"

	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

// monitor keeps a record of who is monitoring a specific target
type monitor struct {
	sync.RWMutex
	m map[string]map[string]bool
}

func (m *monitor) getObserversOf(c string) map[string]bool {
	c = strings.ToLower(c)
	return m.m[c]
}

// add o as an observer of client
func (m *monitor) observe(client, o string) {
	client = strings.ToLower(client)
	o = strings.ToLower(o)

	if m.m[client] == nil {
		m.m[client] = make(map[string]bool)
	}

	m.m[client][o] = true
}

func (m *monitor) unobserve(client, o string) {
	client = strings.ToLower(client)
	o = strings.ToLower(o)

	delete(m.m[client], o)
}

func (m *monitor) list(c string) []string {
	c = strings.ToLower(c)

	list := []string{}
	for client := range m.m {
		if m.getObserversOf(client)[c] {
			list = append(list, client)
		}
	}
	return list
}

// remove c from the observers list of all clients
func (m *monitor) clear(c string) {
	c = strings.ToLower(c)

	for client := range m.m {
		if m.getObserversOf(client)[c] {
			m.unobserve(client, c)
		}
	}
}

func MONITOR(s *Server, c *client.Client, m *msg.Message) {
	if len(m.Params) < 1 {
		s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "MONITOR")
		return
	}

	modifier := m.Params[0]
	switch modifier {
	case "+":
		if len(m.Params) < 2 {
			s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "MONITOR")
			return
		}

		targets := strings.Split(m.Params[1], ",")
		for _, target := range targets {
			s.monitor.observe(target, c.Nick)
			if k := s.clients[target]; k != nil {
				s.writeReply(c, c.Id(), RPL_MONONLINE, k)
			} else {
				s.writeReply(c, c.Id(), RPL_MONOFFLINE, target)
			}
		}
	case "-":
		if len(m.Params) < 2 {
			s.writeReply(c, c.Id(), ERR_NEEDMOREPARAMS, "MONITOR")
			return
		}

		targets := strings.Split(m.Params[1], ",")
		for _, target := range targets {
			s.monitor.unobserve(target, c.Nick)
		}
	case "C":
		s.monitor.clear(c.Nick)
	case "L":
		l := s.monitor.list(c.Nick)
		if len(l) != 0 {
			// TODO: split this into multiple RPL_MONLIST if they go over the line length limit
			s.writeReply(c, c.Id(), RPL_MONLIST, strings.Join(l, ","))
		}
		s.writeReply(c, c.Id(), RPL_ENDOFMONLIST)
	case "S":
		l := s.monitor.list(c.Nick)
		on := []string{}
		off := []string{}

		for _, v := range l {
			if k := s.clients[v]; k != nil {
				on = append(on, k.String())
			} else {
				off = append(off, k.String())
			}
		}

		if len(on) != 0 {
			s.writeReply(c, c.Id(), RPL_MONONLINE, strings.Join(on, ","))
		}
		if len(off) != 0 {
			s.writeReply(c, c.Id(), RPL_MONOFFLINE, strings.Join(off, ","))
		}
	}
}

func (s *Server) notifyOn(c *client.Client) {
	for v := range s.monitor.getObserversOf(c.Nick) {
		if observer, ok := s.getClient(v); ok {
			s.writeReply(observer, observer.Id(), RPL_MONONLINE, c)
			observer.Flush()
		}
	}
}

func (s *Server) notifyOff(c *client.Client) {
	for v := range s.monitor.getObserversOf(c.Nick) {
		if observer, ok := s.getClient(v); ok {
			s.writeReply(observer, observer.Id(), RPL_MONOFFLINE, c.Nick)
			observer.Flush()
		}
	}
}
