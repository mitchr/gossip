package msg

import (
	"fmt"
	"strings"
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
	nick, user, host string // source/prefix information
	Command          string
	Params           []string // command parameters + trailing (if it exists)
	// true if a trailing lexeme is found, even if trailing itself is blank
	// this is used for TOPIC, in which a blank trailing message is significant
	trailingSet bool
}

// TODO: print tags as well
func (m Message) String() string {
	var prefix string
	if m.user != "" {
		prefix = fmt.Sprintf(":%s!%s@%s", m.nick, m.user, m.host)
	} else if m.host != "" {
		prefix = fmt.Sprintf(":%s@%s", m.nick, m.host)
	} else if m.nick != "" {
		prefix = ":" + m.nick
	} else {
		prefix = ":*"
	}

	var params []string
	copy(params, m.Params)
	if m.trailingSet {
		params[len(params)-1] = ":" + params[len(params)-1]
	}

	return fmt.Sprintf("%s %s %s\r\n", prefix, m.Command, strings.Join(params, " "))
}
