package server

import (
	"iter"
	"sync"
)

type safeMap[K comparable, V any] struct {
	l sync.RWMutex
	m map[K]V
}

func NewSafeMap[K comparable, V any]() *safeMap[K, V] {
	s := &safeMap[K, V]{}
	s.m = make(map[K]V)
	return s
}

func (s *safeMap[K, V]) put(k K, v V) {
	s.l.Lock()
	defer s.l.Unlock()
	s.m[k] = v
}

func (s *safeMap[K, V]) get(k K) (V, bool) {
	s.l.RLock()
	defer s.l.RUnlock()
	v, ok := s.m[k]
	return v, ok
}

func (s *safeMap[K, V]) del(k K) {
	s.l.Lock()
	defer s.l.Unlock()
	delete(s.m, k)
}

func (s *safeMap[K, V]) len() int {
	s.l.RLock()
	defer s.l.RUnlock()
	return len(s.m)
}

func (s *safeMap[K, V]) all() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		s.l.RLock()
		defer s.l.RUnlock()
		for k, v := range s.m {
			if !yield(k, v) {
				return
			}
		}
	}
}
