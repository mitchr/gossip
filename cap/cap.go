package cap

// A Capabiltity is a capability that the server implements
type Capability struct {
	Name, Value string
}

var (
	CapNotify   = Capability{"cap-notify", ""}
	MessageTags = Capability{"message-tags", ""}
	MultiPrefix = Capability{"multi-prefix", ""}
)

func (c Capability) String() string { return c.Name }

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
