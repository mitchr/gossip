package util

import (
	"iter"
	"sync"
)

type SafeMap[K comparable, V any] struct {
	l sync.RWMutex
	m map[K]V
}

func NewSafeMap[K comparable, V any]() *SafeMap[K, V] {
	s := &SafeMap[K, V]{}
	s.m = make(map[K]V)
	return s
}

func (s *SafeMap[K, V]) Put(k K, v V) {
	s.l.Lock()
	defer s.l.Unlock()
	s.m[k] = v
}

func (s *SafeMap[K, V]) Get(k K) (V, bool) {
	s.l.RLock()
	defer s.l.RUnlock()
	v, ok := s.m[k]
	return v, ok
}

func (s *SafeMap[K, V]) GetWithoutCheck(k K) V {
	s.l.RLock()
	defer s.l.RUnlock()
	return s.m[k]
}

func (s *SafeMap[K, V]) Del(k K) {
	s.l.Lock()
	defer s.l.Unlock()
	delete(s.m, k)
}

func (s *SafeMap[K, V]) Len() int {
	s.l.RLock()
	defer s.l.RUnlock()
	return len(s.m)
}

func (s *SafeMap[K, V]) All() iter.Seq2[K, V] {
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
