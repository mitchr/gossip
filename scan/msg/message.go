package msg

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type Tag struct {
	// true if this tag is a client only tag
	ClientPrefix bool

	Key string

	// includes vendor as part of value
	Value string
}

// Return raw (unescaped) value of tag
func (t Tag) Raw() string {
	escaped := []rune{}
	for i := 0; i < len(t.Value); i++ {
		if t.Value[i] == '\\' && i+1 < len(t.Value) {
			switch t.Value[i+1] {
			case ':':
				escaped = append(escaped, ';')
			case 's':
				escaped = append(escaped, ' ')
			case '\\':
				escaped = append(escaped, '\\')
			case 'r':
				escaped = append(escaped, '\r')
			case 'n':
				escaped = append(escaped, '\n')
			default:
				escaped = append(escaped, rune(t.Value[i+1]))
			}
			i++
		} else {
			escaped = append(escaped, rune(t.Value[i]))
		}
	}
	return string(escaped)
}

type Msg interface {
	Bytes() []byte
	AddTag(k, v string)
	SetMsgid()
	RemoveAllTags() Msg
	EstimateMessageSize() int
}

// Message represents a single irc message
type Message struct {
	tags             []Tag
	Nick, User, Host string // source/prefix information
	Command          string
	Params           []string // command parameters + trailing (if it exists)
	// true if a trailing lexeme is found, even if trailing itself is blank
	// this is used for TOPIC, in which a blank trailing message is significant
	trailingSet bool
}

func New(tags []Tag, nick, user, host, command string, params []string, trailing bool) *Message {
	tagCopy := make([]Tag, len(tags))
	copy(tagCopy, tags)
	return &Message{tagCopy, nick, user, host, strings.ToUpper(command), params, trailing}
}

func (m Message) EstimateMessageSize() int {
	n := len(m.Nick) + len(m.User) + len(m.Host) + 3 // 3 bytes for ':!@'
	n += len(m.Command)

	n += m.sizeOfTags()
	for _, v := range m.Params {
		n += len(v) + 1 // 1 additional bytes for space
	}
	if m.trailingSet {
		n += 1 // 1 bytes for ':'
	}

	// 2 bytes for crlf
	n += 2
	return n
}

func (m Message) Bytes() []byte {
	var b bytes.Buffer
	b.Grow(m.EstimateMessageSize())

	var tagCount int
	for _, v := range m.tags {
		if tagCount == 0 {
			b.WriteByte('@')
		}

		if v.ClientPrefix {
			b.WriteByte('+')
		}
		b.WriteString(v.Key)
		if v.Value != "" {
			b.WriteByte('=')
			b.WriteString(v.Value)
		}

		if tagCount == len(m.tags)-1 {
			b.WriteByte(' ')
		} else {
			b.WriteByte(';')
		}

		tagCount++
	}

	if m.Nick != "" {
		b.WriteByte(':')
		b.WriteString(m.Nick)
	}
	if m.User != "" {
		b.WriteByte('!')
		b.WriteString(m.User)
	}
	if m.Host != "" {
		b.WriteByte('@')
		b.WriteString(m.Host)
	}
	if m.Nick != "" || m.User != "" || m.Host != "" {
		b.WriteByte(' ')
	}

	b.WriteString(m.Command)

	for i, v := range m.Params {
		b.WriteByte(' ')
		if i == len(m.Params)-1 && m.trailingSet {
			b.WriteByte(':')
		}
		b.WriteString(v)
	}

	b.WriteByte('\r')
	b.WriteByte('\n')

	return b.Bytes()
}

func (m Message) String() string {
	return string(m.Bytes())
}

func (m Message) NUH() string {
	if m.User != "" {
		return m.Nick + "!" + m.User + "@" + m.Host
	} else if m.Host != "" {
		return m.Nick + "@" + m.Host
	} else if m.Nick != "" {
		return m.Nick
	} else {
		return ""
	}
}

func (m *Message) AddTag(k, v string) {
	m.tags = append(m.tags, Tag{Key: k, Value: v})
}

func (m *Message) HasTag(k string) (bool, string) {
	for _, v := range m.tags {
		if v.Key == k {
			return true, v.Value
		}
	}
	return false, ""
}

// Generate a unique uuid for this message. Subsequent calls to SetMsgid
// do not change the id.
func (m *Message) SetMsgid() {
	if exists, _ := m.HasTag("msgid"); exists {
		return
	}

	m.AddTag("msgid", uuid.NewString())
}

func (m *Message) sizeOfTags() int {
	if len(m.tags) == 0 {
		return 0
	}

	// acocunt for leading '@' and trailing ' '
	size := 2

	tagCount := 0
	for _, v := range m.tags {
		size += len(v.Key)

		if v.ClientPrefix {
			size++ // acocunt for '+'
		}
		if v.Value != "" {
			size += len(v.Value) + 1 // account for '='
		}

		// this is not the last tag, so account for ';' between tags
		if tagCount != len(m.tags)-1 {
			size++
		}
		tagCount++
	}

	return size
}

func (m *Message) TrimNonClientTags() {
	trimmed := []Tag{}
	for _, v := range m.tags {
		if v.ClientPrefix {
			trimmed = append(trimmed, v)
		}
	}
	m.tags = trimmed
}

// Return a copy of the message with the tags removed. Used for sending
// messages to clients that do not support message-tags
func (m Message) RemoveAllTags() Msg {
	m.tags = nil
	return &m
}

func (m Message) Format(a ...interface{}) *Message {
	aPos := 0
	newParams := make([]string, len(m.Params))

	for i := 0; i < len(m.Params); i++ {
		c := strings.Count(m.Params[i], "%")

		if aPos+c > len(a) {
			newParams[i] = fmt.Sprintf(m.Params[i], a[aPos:]...)
			m.Params = newParams
			return &m
		} else {
			newParams[i] = fmt.Sprintf(m.Params[i], a[aPos:aPos+c]...)
		}

		aPos += c
	}

	m.Params = newParams
	return &m
}
