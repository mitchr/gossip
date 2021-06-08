package scan

type queue struct {
	head, tail *Token
}

// insert at end of queue
func (q *queue) offer(t *Token) {
	if q.head == nil {
		q.tail = t
		q.head = q.tail
		return
	}

	q.tail.next = t
	q.tail = q.tail.next
}

func (q *queue) poll() *Token {
	t := q.head
	if q.head != nil {
		q.head = q.head.next
	}
	return t
}

func (q *queue) peek() *Token { return q.head }
