package scan

type TokQueue struct {
	front int16
	end   int16
	buf   []Token
}

func New(size int) TokQueue { return TokQueue{front: -1, end: -1, buf: make([]Token, size)} }

func (t *TokQueue) Reset() { t.front = 0 }

func (t TokQueue) TryToExtractCommand() string {
	var s string
	for i := 0; i < int(t.end); i++ {
		if t.buf[i].Value == ' ' {
			return s
		}
		s += string(t.buf[i].Value)
	}
	return s
}

func (a *TokQueue) Peek() Token {
	if a.front == -1 || int(a.front) > len(a.buf)-1 {
		return EOFToken
	}
	return a.buf[a.front]
}

func (a *TokQueue) push(t Token) {
	if a.front == -1 {
		a.front++
		a.end = a.front
		a.buf[a.end] = t
		return
	}
	a.end++
	a.buf[a.end] = t
}

func (a *TokQueue) pop() Token {
	if a.front == -1 || int(a.front) > len(a.buf)-1 {
		return EOFToken
	}

	t := a.buf[a.front]
	a.front++
	return t
}
