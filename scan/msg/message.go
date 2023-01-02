package msg

import (
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
	// cleanedTags := make(map[string]TagVal, len(tags))
	// for k, v := range tags {
	// 	cleanedTags[k] = TagVal{Value: v}
	// }
	return &Message{tags, nick, user, host, command, params, trailing}
}

func (m Message) estimateMessageSize() int {
	n := len(m.Nick) + len(m.User) + len(m.Host) + len(m.Command)

	n += m.SizeOfTags()
	for _, v := range m.Params {
		n += len(v)
	}
	if m.trailingSet {
		n += 1
	}
	return n
}

func (m Message) String() string {
	var s strings.Builder
	s.Grow(m.estimateMessageSize())

	var tagCount int
	for _, v := range m.tags {
		if tagCount == 0 {
			s.WriteByte('@')
		}

		if v.ClientPrefix {
			s.WriteByte('+')
		}
		s.WriteString(v.Key)
		if v.Value != "" {
			s.WriteByte('=')
			s.WriteString(v.Value)
		}

		if tagCount == len(m.tags)-1 {
			s.WriteByte(' ')
		} else {
			s.WriteByte(';')
		}

		tagCount++
	}

	if m.Nick != "" {
		s.WriteByte(':')
		s.WriteString(m.Nick)
	}
	if m.User != "" {
		s.WriteByte('!')
		s.WriteString(m.User)
	}
	if m.Host != "" {
		s.WriteByte('@')
		s.WriteString(m.Host)
	}
	if m.Nick != "" || m.User != "" || m.Host != "" {
		s.WriteByte(' ')
	}

	s.WriteString(m.Command)

	for i, v := range m.Params {
		s.WriteByte(' ')
		if i == len(m.Params)-1 && m.trailingSet {
			s.WriteByte(':')
		}
		s.WriteString(v)
	}

	s.WriteByte('\r')
	s.WriteByte('\n')

	return s.String()
}

func (m *Message) AddTag(k, v string) {
	m.tags = append(m.tags, Tag{Key: k, Value: v})
}

// Generate a unique uuid for this message. Subsequent calls to SetMsgid
// do not change the id.
func (m *Message) SetMsgid() {
	for _, v := range m.tags {
		if v.Value == "msgid" {
			return
		}
	}
	m.AddTag("msgid", uuid.NewString())
}

func (m *Message) SizeOfTags() int {
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
func (m Message) RemoveAllTags() *Message {
	m.tags = nil
	return &m
}
