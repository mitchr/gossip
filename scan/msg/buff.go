package msg

import "github.com/google/uuid"

type BatchType string

const (
	Label BatchType = "labeled-response"
)

type MsgBuffer struct {
	label string
	msgs  []Msg
}

func NewBatch(label string) *MsgBuffer {
	return &MsgBuffer{label: label}
}

func (b *MsgBuffer) Len() int { return len(b.msgs) }

// Batch all messages together. The caller should not call AddMsg after WrapInBatch.
func (b *MsgBuffer) WrapInBatch(batchType BatchType) {
	// single responses don't need to be BATCHed
	if b.Len() == 1 {
		return
	}

	batchLabel := uuid.New().String()
	start := New(nil, "", "", "", "BATCH", []string{"+" + batchLabel, string(batchType)}, false)
	end := New(nil, "", "", "", "BATCH", []string{"-" + batchLabel}, false)
	b.msgs = append([]Msg{start}, append(b.msgs, end)...)
}

func (b *MsgBuffer) AddMsg(m Msg) {
	b.msgs = append(b.msgs, m)
}

func (b *MsgBuffer) Bytes() []byte {
	buf := []byte{}
	for _, v := range b.msgs {
		buf = append(buf, v.Bytes()...)
	}
	return buf
}

func (b *MsgBuffer) AddTag(k, v string) {
	for i := range b.msgs {
		b.msgs[i].AddTag(k, v)
	}
}

func (b *MsgBuffer) SetMsgid() {
	for i := range b.msgs {
		b.msgs[i].SetMsgid()
	}
}

func (b *MsgBuffer) RemoveAllTags() Msg {
	for i := range b.msgs {
		b.msgs[i] = b.msgs[i].RemoveAllTags()
	}
	return b
}
