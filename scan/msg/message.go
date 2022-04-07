package msg

import (
	"fmt"

	"github.com/google/uuid"
)

// A TagVal represents the value associated with a message tag
type TagVal struct {
	// true if this tag is a client only tag
	ClientPrefix  bool
	Vendor, Value string
}

// Return raw (unescaped) value of tag
func (t TagVal) Raw() string {
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
	tags             map[string]TagVal
	Nick, User, Host string // source/prefix information
	Command          string
	Params           []string // command parameters + trailing (if it exists)
	// true if a trailing lexeme is found, even if trailing itself is blank
	// this is used for TOPIC, in which a blank trailing message is significant
	trailingSet bool
}

func New(tags map[string]string, nick, user, host, command string, params []string, trailing bool) *Message {
	cleanedTags := make(map[string]TagVal, len(tags))
	for k, v := range tags {
		cleanedTags[k] = TagVal{false, "", v}
	}
	return &Message{cleanedTags, nick, user, host, command, params, trailing}
}

func (m Message) String() string {
	var tags string
	var tagCount int
	for k, v := range m.tags {
		if tagCount == 0 {
			tags += "@"
		}

		if v.ClientPrefix {
			tags += "+"
		}
		if v.Vendor != "" {
			tags += v.Vendor + "/"
		}
		tags += k
		if v.Value != "" {
			tags += "=" + v.Value
		}

		if tagCount == len(m.tags)-1 {
			tags += " "
		} else {
			tags += ";"
		}

		tagCount++
	}

	var prefix string
	if m.User != "" {
		prefix = fmt.Sprintf(":%s!%s@%s ", m.Nick, m.User, m.Host)
	} else if m.Host != "" {
		prefix = fmt.Sprintf(":%s@%s ", m.Nick, m.Host)
	} else if m.Nick != "" {
		prefix = ":" + m.Nick + " "
	}

	var params string
	for i, v := range m.Params {
		if i == len(m.Params)-1 && m.trailingSet {
			v = ":" + v
		}
		params += " " + v
	}

	return tags + prefix + m.Command + params + "\r\n"
}

func (m *Message) AddTag(k, v string) {
	if m.tags == nil {
		m.tags = make(map[string]TagVal)
	}
	m.tags[k] = TagVal{false, "", v}
}

// Generate a unique uuid for this message. Subsequent calls to SetMsgid
// do not change the id.
func (m *Message) SetMsgid() {
	if _, ok := m.tags["msgid"]; ok {
		return
	}
	m.AddTag("msgid", uuid.NewString())
}

func (m Message) TrimNonClientTags() {
	for k, v := range m.tags {
		if !v.ClientPrefix {
			delete(m.tags, k)
		}
	}
}

// Return a copy of the message with the tags removed. Used for sending
// messages to clients that do not support message-tags
func (m Message) RemoveAllTags() *Message {
	m.tags = nil
	return &m
}
