package cap

// A Capabiltity is a capability that the server implements
type Capability struct {
	Name, Value string
}

var (
	CapNotify   = Capability{"cap-notify", ""}
	MessageTags = Capability{"message-tags", ""}
	// MultiPrefix = Capability{"multi-prefix", ""}
)

func (c Capability) String() string { return c.Name }

var Caps = map[string]Capability{
	"cap-notify":   CapNotify,
	"message-tags": MessageTags,
	// "multi-prefix": MultiPrefix,
}
