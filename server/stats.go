package server

import "sync"

type statistic struct {
	u uint
	sync.Mutex
}

func (s *statistic) Inc() {
	s.Lock()
	defer s.Unlock()

	s.u++
}

func (s *statistic) Dec() {
	s.Lock()
	defer s.Unlock()

	s.u--
}

func (s *statistic) Get() uint {
	s.Lock()
	defer s.Unlock()

	return s.u
}

func (s *statistic) KeepMax(t uint) uint {
	s.Lock()
	defer s.Unlock()

	if t > s.u {
		s.u = t
	}
	return s.u
}
