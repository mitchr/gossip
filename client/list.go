package client

import (
	"fmt"
)

type node struct {
	next *node
	data *Client
}

type List struct {
	head *node
}

func (l *List) String() string {
	str := ""

	current := l.head
	for current != nil {
		str += fmt.Sprintf("%d->", current.data)
		current = current.next
	}

	return str
}

func (l *List) Len() int {
	i := 0
	current := l.head
	for current != nil {
		i++
		current = current.next
	}
	return i
}

func (l *List) Add(d *Client) {
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
