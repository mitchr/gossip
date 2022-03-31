package server

import "sync"

// whowasStack keeps track of WHOWAS information
type whowasStack struct {
	head *node
	size int

	sync.RWMutex
}

type whowasInfo struct{ nick, user, host, realname string }

type node struct {
	next *node
	data whowasInfo
}

func (l *whowasStack) push(nick, user, host, realname string) {
	l.Lock()
	defer l.Unlock()

	l.head = &node{l.head, whowasInfo{nick, user, host, realname}}
	l.size++
}

// search searches the stack for occurences of nick, starting with the
// most recent entries first. If count > 1, up to a count number of
// entries will be returned.
func (l *whowasStack) search(nick string, count int) []*whowasInfo {
	l.RLock()
	defer l.RUnlock()

	matches := make([]*whowasInfo, 0, count)

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
