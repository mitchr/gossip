package server

import (
	"iter"
	"sync"
)

// whowasStack keeps track of WHOWAS information
type whowasStack struct {
	head *node
	size int

	m sync.RWMutex
}

type whowasInfo struct{ nick, user, host, realname string }

type node struct {
	next *node
	data whowasInfo
}

func (l *whowasStack) len() int {
	l.m.RLock()
	defer l.m.RUnlock()
	return l.size
}

func (l *whowasStack) push(nick, user, host, realname string) {
	l.m.Lock()
	defer l.m.Unlock()

	l.head = &node{l.head, whowasInfo{nick, user, host, realname}}
	l.size++
}

// search searches the stack for any occurence of any nick in nicks,
// starting with the most recent entries first. If count > 1, up to a
// count number of entries will be returned.
func (l *whowasStack) search(nicks []string, count int) iter.Seq[*whowasInfo] {
	return func(yield func(*whowasInfo) bool) {
		l.m.RLock()
		defer l.m.RUnlock()

		i := 1
		for current := l.head; current != nil && i <= count; current = current.next {
			for _, n := range nicks {
				if current.data.nick != n {
					continue
				}

				i++
				if !yield(&current.data) {
					return
				}
			}
		}
	}
}
