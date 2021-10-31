package cap

// A Capabiltity is a capability that the server implements
type Capability struct {
	Name, Value string
}

func (c Capability) String() string { return c.Name }

var (
	CapNotify   = Capability{Name: "cap-notify"}
	MessageTags = Capability{Name: "message-tags"}
	STS         = Capability{Name: "sts", Value: "port=%s,duration=%.f"}
	SASL        = Capability{Name: "sasl", Value: "PLAIN,EXTERNAL,SCRAM"}
	// MultiPrefix = Capability{"multi-prefix", ""}
)

var SupportedCaps = map[string]Capability{
	CapNotify.Name:   CapNotify,
	MessageTags.Name: MessageTags,
	STS.Name:         STS,
	SASL.Name:        SASL,
	// "multi-prefix": MultiPrefix,
}
