package cap

// A Capabiltity is a capability that the server implements
type Capability struct {
	Name, Value string
}

var (
	CapNotify   = Capability{Name: "cap-notify"}
	MessageTags = Capability{Name: "message-tags"}
	STS         = Capability{Name: "sts", Value: "port=%s,duration=%.f"}
	// MultiPrefix = Capability{"multi-prefix", ""}
)

func (c Capability) String() string { return c.Name }

var Caps = map[string]Capability{
	CapNotify.Name:   CapNotify,
	MessageTags.Name: MessageTags,
	STS.Name:         STS,
	// "multi-prefix": MultiPrefix,
}
