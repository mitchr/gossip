package cap

// A Capabiltity is a capability that the server implements
type Capability int

const (
	MessageTags Capability = iota
	MultiPrefix
)

func (c Capability) String() string {
	return []string{"message-tags", "multi-prefix"}[c]
}

var Caps = map[string]Capability{
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
