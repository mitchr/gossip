package util

import (
	"fmt"
	"sync"
)

type Equaler interface {
	Equals(interface{}) bool
}

type List struct {
	data []interface{}
	m    *sync.Mutex
}

func NewList() List {
	return List{m: new(sync.Mutex)}
}

func (l List) String() string {
	s := ""
	for _, v := range l.data {
		s += fmt.Sprintf("%v ", v)
	}
	return s
}
func (l *List) Add(e interface{}) {
	l.m.Lock()
	defer l.m.Unlock()

	l.data = append(l.data, e)
}

func (l List) Get(i int) interface{} {
	l.m.Lock()
	defer l.m.Unlock()

	return l.data[i]
}

func (l List) Len() int {
	l.m.Lock()
	defer l.m.Unlock()

	return len(l.data)
}

func (l *List) removeAtIndex(i int) {
	l.data = append(l.data[:i], l.data[i+1:]...)
}

func (l *List) Remove(e interface{}) {
	l.m.Lock()
	defer l.m.Unlock()

	for i := 0; i < len(l.data); i++ {
		switch t := l.data[i].(type) {
		case Equaler:
			if t.Equals(e) {
				l.removeAtIndex(i)
				return
			}
		default:
			if t == e {
				l.removeAtIndex(i)
				return
			}
		}
	}
}

func (l List) Find(i interface{}) interface{} {
	l.m.Lock()
	defer l.m.Unlock()

	for _, v := range l.data {
		switch t := v.(type) {
		case Equaler:
			if t.Equals(i) {
				return v
			}
		default:
			if t == i {
				return v
			}
		}
	}
	return nil
}
