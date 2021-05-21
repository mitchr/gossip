package msg

import (
	"fmt"
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

// a Message represents a single irc Message
type Message struct {
	tags             map[string]TagVal
	Nick, User, Host string // source/prefix information
	Command          string
	Params           []string // command parameters + trailing (if it exists)
	// true if a trailing lexeme is found, even if trailing itself is blank
	// this is used for TOPIC, in which a blank trailing message is significant
	trailingSet bool
}

func (m Message) String() string {
	var tags string
	if len(m.tags) > 0 {
		tags += "@"
	}
	for k, v := range m.tags {
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
		tags += ";"
	}
	if len(tags) > 0 {
		tags = tags[:len(tags)-1] // chop off ending ';'
		tags += " "
	}

	var prefix string
	if m.User != "" {
		prefix = fmt.Sprintf(":%s!%s@%s", m.Nick, m.User, m.Host)
	} else if m.Host != "" {
		prefix = fmt.Sprintf(":%s@%s", m.Nick, m.Host)
	} else if m.Nick != "" {
		prefix = ":" + m.Nick
	}

	var params string
	for i, v := range m.Params {
		if i == 0 {
			params += " "
		}
		if i == len(m.Params)-1 {
			params += ":"
		}
		params += v + " "
	}
	if len(params) > 0 {
		params = params[:len(params)-1] // chop off ' '
	}

	return tags + prefix + " " + m.Command + params
}

func (m *Message) TrimNonClientTags() {
	for k, v := range m.tags {
		if !v.ClientPrefix {
			delete(m.tags, k)
		}
	}
}
