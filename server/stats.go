package server

import "sync/atomic"

type statistic uint64

func (s *statistic) Inc() {
	atomic.AddUint64((*uint64)(s), 1)
}

func (s *statistic) Dec() {
	atomic.AddUint64((*uint64)(s), ^uint64(0))
}

func (s *statistic) Get() uint64 {
	return atomic.LoadUint64((*uint64)(s))
}

// If t is larger than s, replace the value of s with t. Returns the
// maximum value of s after the replacement.
func (s *statistic) KeepMax(t uint64) uint64 {
	for {
		v := atomic.LoadUint64((*uint64)(s))
		if t <= v {
			return v
		}

		// successfully performed s<-t, return t
		if atomic.CompareAndSwapUint64((*uint64)(s), v, t) {
			return t
		}
	}
}
