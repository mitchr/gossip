package msg

import (
	"bytes"
	"testing"
)

func TestBuffWrapInBatch(t *testing.T) {
	buff := Buffer{}
	m1 := New(nil, "", "", "", "", nil, false)
	m2 := New(nil, "", "", "", "", nil, false)
	buff.AddMsg(m1)
	buff.AddMsg(m2)

	if buff.WrapInBatch(Label).Len() != 4 {
		t.Errorf("Failed to wrap Buff in batch; len is %v", buff.Len())
	}
}

func TestBuffSetMsgId(t *testing.T) {
	buff := Buffer{}
	m1 := New(nil, "", "", "", "", nil, false)
	m2 := New(nil, "", "", "", "", nil, false)
	buff.AddMsg(m1)
	buff.AddMsg(m2)
	buff.SetMsgid()

	msgs := bytes.Split(buff.Bytes(), []byte{'\r', '\n'})
	for _, v := range msgs {
		if len(v) == 0 {
			continue
		}

		if !bytes.Contains(v, []byte("@msgid")) {
			t.Errorf("%v did not contain '@msgid'", v)
		}
	}
}

func TestBuffRemoveAllTags(t *testing.T) {
	buff := Buffer{}
	m1 := New(nil, "", "", "", "", nil, false)
	m2 := New(nil, "", "", "", "", nil, false)
	buff.AddMsg(m1)
	buff.AddMsg(m2)
	buff.SetMsgid()
	buff.RemoveAllTags()

	msgs := bytes.Split(buff.Bytes(), []byte{'\r', '\n'})
	for _, v := range msgs {
		if len(v) == 0 {
			continue
		}

		if bytes.Contains(v, []byte("@msgid")) {
			t.Errorf("%v contained '@msgid'", v)
		}
	}
}

func BenchmarkBuffWrapInBatch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()

		buff := Buffer{}
		m1 := New(nil, "", "", "", "", nil, false)
		m2 := New(nil, "", "", "", "", nil, false)
		buff.AddMsg(m1)
		buff.AddMsg(m2)

		b.StartTimer()

		buff.WrapInBatch(Label)
	}
}

func BenchmarkBuffAdd(b *testing.B) {
	buff := Buffer{}
	m := New(nil, "", "", "", "", nil, false)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buff.AddMsg(m)
	}
}
