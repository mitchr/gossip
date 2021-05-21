package cap

// A Capabiltity is a capability that the server implements
type Capability int

const (
	CapNotify Capability = iota
	MessageTags
	MultiPrefix
)

func (c Capability) String() string {
	return []string{"cap-notify", "message-tags", "multi-prefix"}[c]
}

var Caps = map[string]Capability{
	"cap-notify":   CapNotify,
	"message-tags": MessageTags,
	"multi-prefix": MultiPrefix,
}

func StringSlice(c []Capability) []string {
	s := make([]string, len(c))
	for i := 0; i < len(c); i++ {
		s[i] = c[i].String()
	}
	return s
}
