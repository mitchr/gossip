package server

import "sync"

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

// search searches the stack for occurences of nick, starting with the
// most recent entries first. If count > 1, up to a count number of
// entries will be returned.
func (l *whowasStack) search(nick string, count int) []*whowasInfo {
	matches := make([]*whowasInfo, 0, count)

	l.m.RLock()
	defer l.m.RUnlock()

	i := 1
	current := l.head
	for current != nil && i <= count {
		if current.data.nick == nick {
			matches = append(matches, &current.data)
			i++
		}

		current = current.next
	}

	return matches
}
