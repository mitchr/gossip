package server

import "sync"

type statistic struct {
	u uint
	m sync.Mutex
}

func (s *statistic) Inc() {
	s.m.Lock()
	defer s.m.Unlock()

	s.u++
}

func (s *statistic) Dec() {
	s.m.Lock()
	defer s.m.Unlock()

	s.u--
}

func (s *statistic) Get() uint {
	s.m.Lock()
	defer s.m.Unlock()

	return s.u
}

func (s *statistic) KeepMax(t uint) uint {
	s.m.Lock()
	defer s.m.Unlock()

	if t > s.u {
		s.u = t
	}
	return s.u
}
