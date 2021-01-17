package client

import (
	"fmt"
	"sync"
)

type node struct {
	next *node
	data *Client
}

type List struct {
	head *node
	m    sync.Mutex
}

func (l *List) String() string {
	l.m.Lock()
	defer l.m.Unlock()

	str := ""

	current := l.head
	for current != nil {
		str += fmt.Sprintf("%v->", current.data)
		current = current.next
	}

	return str
}

func (l *List) Len() int {
	l.m.Lock()
	defer l.m.Unlock()

	i := 0
	current := l.head
	for current != nil {
		i++
		current = current.next
	}
	return i
}

func (l *List) Add(d *Client) {
	l.m.Lock()
	defer l.m.Unlock()

	if l.head == nil {
		l.head = &node{nil, d}
	} else {
		current := l.head
		for current.next != nil {
			current = current.next
		}
		current.next = &node{nil, d}
	}
}

// returns true if element was found and removed
// otherwise false
func (l *List) Remove(d *Client) bool {
	l.m.Lock()
	defer l.m.Unlock()

	current := l.head
	previous := current

	// if need to remove head
	if current.data == d {
		l.head = l.head.next
		return true
	}

	for current != nil {
		if current.data == d {
			// if this is the last not in the link
			if current.next == nil {
				previous.next = nil
			} else { // not the last or first node
				current.next = current.next.next
			}
			return true
		}
		previous = current
		current = current.next
	}
	return false
}

func (l *List) Get(i int) *Client {
	j := 0
	current := l.head
	for current != nil {
		if j == i {
			return current.data
		}
		j++
		current = current.next
	}
	return nil
}

func (l *List) SearchNick(nickName string) *Client {
	for current := l.head; current.next != nil; current = current.next {
		if current.data.Nick == nickName {
			return current.data
		}
	}
	return nil
}
