package util

import (
	"fmt"
)

type Equaler interface {
	Equals(interface{}) bool
}

type List []interface{}

func (l List) String() string {
	s := ""
	for _, v := range l {
		s += fmt.Sprintf("%v ", v)
	}
	return s
}

func (l *List) Add(e interface{}) { *l = append(*l, e) }
func (l List) Get(i int) interface{} {
	if i < 0 || i >= len(l) {
		return nil
	}
	return l[i]
}

func (l List) Len() int             { return len(l) }
func (l *List) removeAtIndex(i int) { *l = append((*l)[:i], (*l)[i+1:]...) }
func (l *List) Remove(e interface{}) {
	for i, v := range *l {
		switch t := v.(type) {
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
	for _, v := range l {
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

func (l *List) ForEach(f func(interface{})) {
	for _, v := range *l {
		f(v)
	}
}
