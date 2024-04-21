package msg

import (
	"github.com/google/uuid"
)

type BatchType string

const (
	Label BatchType = "labeled-response"
)

type Buffer []Msg

func (b Buffer) Len() int { return len(b) }

// Batch all messages together. The caller should not call AddMsg after WrapInBatch.
func (b Buffer) WrapInBatch(batchType BatchType) Buffer {
	// single responses don't need to be BATCHed
	if b.Len() == 1 {
		return b
	}

	batchLabel := uuid.New().String()
	start := New(nil, "", "", "", "BATCH", []string{"+" + batchLabel, string(batchType)}, false)
	end := New(nil, "", "", "", "BATCH", []string{"-" + batchLabel}, false)
	b = append([]Msg{start}, append(b, end)...)

	b.AddTag("batch", batchLabel)
	return b
}

func (b *Buffer) AddMsg(m Msg) {
	switch m := m.(type) {
	case Buffer:
		*b = append(*b, m...)
	default:
		*b = append(*b, m)
	}
}

func (b Buffer) EstimateMessageSize() int {
	size := 0
	for _, v := range b {
		size += v.EstimateMessageSize()
	}
	return size
}

func (b Buffer) Bytes() []byte {
	buf := make([]byte, 0, b.EstimateMessageSize())
	for _, v := range b {
		buf = append(buf, v.Bytes()...)
	}
	return buf
}

func (b Buffer) AddTag(k, v string) {
	for i := range b {
		b[i].AddTag(k, v)
	}
}

func (b Buffer) SetMsgid() {
	for i := range b {
		b[i].SetMsgid()
	}
}

func (b Buffer) RemoveAllTags() Msg {
	for i := range b {
		b[i] = b[i].RemoveAllTags()
	}
	return b
}
