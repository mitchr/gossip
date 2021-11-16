package cap

// A Capabiltity is a capability that the server implements
type Capability struct {
	Name, Value string
}

func (c Capability) String() string { return c.Name }

var (
	CapNotify   = Capability{Name: "cap-notify"}
	EchoMessage = Capability{Name: "echo-message"}
	MessageTags = Capability{Name: "message-tags"}
	ServerTime  = Capability{Name: "server-time"}
	STS         = Capability{Name: "sts", Value: "port=%s,duration=%.f"}
	SASL        = Capability{Name: "sasl", Value: "PLAIN,EXTERNAL,SCRAM"}
	// MultiPrefix = Capability{"multi-prefix", ""}
)

func IsRecognized(c string) bool {
	return c == CapNotify.Name || c == EchoMessage.Name || c == MessageTags.Name || c == SASL.Name || c == ServerTime.Name || c == STS.Name
}
