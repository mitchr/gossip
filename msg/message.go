package msg

import "fmt"

// a Message represents a single irc Message
type Message struct {
	tags             map[string]string
	nick, user, host string // source/prefix information
	Command          string
	middle           []string // command parameters
	trailing         string   // also a command parameter but after ':'
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

	var params string
	for _, v := range m.middle {
		params += v + " "
	}
	if m.trailing != "" {
		params += ":" + m.trailing
	} else {
		params = params[:len(params)-1] // trim trailing space
	}

	return fmt.Sprintf("%s %s %s\r\n", prefix, m.Command, params)
}

// merge middle and trailing into one slice
func (m Message) Parameters() []string {
	if m.trailing == "" {
		return m.middle
	}
	return append(m.middle, m.trailing)
}
