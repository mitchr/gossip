package scan

type Queue struct {
	head *node
	tail *node
}

type node struct {
	next  *node
	value Token
}

func (q *Queue) IsEmpty() bool { return q.head == nil }

func (q *Queue) peek() Token {
	if q.head == nil {
		return EOFToken
	}
	return q.head.value
}

func (q *Queue) offer(t Token) {
	if q.head == nil {
		q.head = &node{nil, t}
		q.tail = q.head
		return
	}

	q.tail.next = &node{nil, t}
	q.tail = q.tail.next
}

func (q *Queue) poll() Token {
	if q.head == nil {
		return EOFToken
	}

	start := q.head
	q.head = q.head.next
	return start.value
}
