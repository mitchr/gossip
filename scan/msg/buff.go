package msg

import "github.com/google/uuid"

type BatchType string

const (
	Label BatchType = "labeled-response"
)

type Buffer struct {
	msgs []Msg
}

func (b *Buffer) Len() int { return len(b.msgs) }

// Batch all messages together. The caller should not call AddMsg after WrapInBatch.
func (b *Buffer) WrapInBatch(batchType BatchType) *Buffer {
	// single responses don't need to be BATCHed
	if b.Len() == 1 {
		return b
	}

	batchLabel := uuid.New().String()
	start := New(nil, "", "", "", "BATCH", []string{"+" + batchLabel, string(batchType)}, false)
	end := New(nil, "", "", "", "BATCH", []string{"-" + batchLabel}, false)
	b.msgs = append([]Msg{start}, append(b.msgs, end)...)

	b.AddTag("batch", batchLabel)
	return b
}

func (b *Buffer) AddMsg(m Msg) {
	switch m := m.(type) {
	case *Message:
		b.msgs = append(b.msgs, m)
	case *Buffer:
		b.msgs = append(b.msgs, m.msgs...)
	}

}

func (b *Buffer) Bytes() []byte {
	buf := []byte{}
	for _, v := range b.msgs {
		buf = append(buf, v.Bytes()...)
	}
	return buf
}

func (b *Buffer) AddTag(k, v string) {
	for i := range b.msgs {
		b.msgs[i].AddTag(k, v)
	}
}

func (b *Buffer) SetMsgid() {
	for i := range b.msgs {
		b.msgs[i].SetMsgid()
	}
}

func (b *Buffer) RemoveAllTags() Msg {
	for i := range b.msgs {
		b.msgs[i] = b.msgs[i].RemoveAllTags()
	}
	return b
}
