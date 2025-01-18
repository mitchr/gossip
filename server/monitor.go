package server

import (
	"strings"
	"sync"

	"github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/client"
	"github.com/mitchr/gossip/scan/msg"
)

// monitor keeps a record of who is monitoring a specific target
// m[client] is a map of observers of client
// m[client][observer] == true means observer obvserves client
type monitor struct {
	rwLock sync.RWMutex
	m      map[string]map[string]bool
}

func (m *monitor) getObserversOf(c string) map[string]bool {
	c = strings.ToLower(c)

	m.rwLock.RLock()
	defer m.rwLock.RUnlock()

	return m.m[c]
}

// add o as an observer of client
func (m *monitor) observe(client, o string) {
	client = strings.ToLower(client)
	o = strings.ToLower(o)

	m.rwLock.Lock()
	defer m.rwLock.Unlock()

	if m.m[client] == nil {
		m.m[client] = make(map[string]bool)
	}

	m.m[client][o] = true
}

func (m *monitor) unobserve(client, o string) {
	client = strings.ToLower(client)
	o = strings.ToLower(o)

	m.rwLock.Lock()
	defer m.rwLock.Unlock()

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

func MONITOR(s *Server, c *client.Client, m *msg.Message) msg.Msg {
	if len(m.Params) < 1 {
		return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "MONITOR")
	}

	modifier := m.Params[0]
	switch modifier {
	case "+":
		if len(m.Params) < 2 {
			return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "MONITOR")
		}

		targets := strings.Split(m.Params[1], ",")
		for _, target := range targets {
			s.monitor.observe(target, c.Nick)
			if k, _ := s.clients.get(target); k != nil {
				s.writeReply(c, RPL_MONONLINE, k)
			} else {
				s.writeReply(c, RPL_MONOFFLINE, target)
			}
		}
	case "-":
		if len(m.Params) < 2 {
			return prepMessage(ERR_NEEDMOREPARAMS, s.Name, c.Id(), "MONITOR")
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
			s.writeReply(c, RPL_MONLIST, strings.Join(l, ","))
		}
		s.writeReply(c, RPL_ENDOFMONLIST)
	case "S":
		l := s.monitor.list(c.Nick)
		on := []string{}
		off := []string{}

		for _, v := range l {
			if k, _ := s.clients.get(v); k != nil {
				on = append(on, k.String())
			} else {
				off = append(off, v)
			}
		}

		if len(on) != 0 {
			s.writeReply(c, RPL_MONONLINE, strings.Join(on, ","))
		}
		if len(off) != 0 {
			s.writeReply(c, RPL_MONOFFLINE, strings.Join(off, ","))
		}
	}
	return nil
}

func (s *Server) notify(c *client.Client, m *msg.Message, extended capability.Cap) {
	s.monitor.rwLock.RLock()
	defer s.monitor.rwLock.RUnlock()

	for v := range s.monitor.getObserversOf(c.Nick) {
		observer, ok := s.getClient(v)
		if !ok {
			continue
		}
		_, hasExtendedMonitor := observer.Caps[capability.ExtendedMonitor.Name]
		_, hasExtendedCapability := observer.Caps[extended.Name]
		if extended != capability.None && (!hasExtendedMonitor || !hasExtendedCapability) {
			continue
		}

		observer.WriteMessage(m)
	}
}
