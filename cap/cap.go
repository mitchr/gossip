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

func IsRecognized(c string) bool {
	return c == CapNotify.Name || c == MessageTags.Name || c == STS.Name || c == SASL.Name
}
