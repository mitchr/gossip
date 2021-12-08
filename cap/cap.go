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
	SASL        = Capability{Name: "sasl", Value: "PLAIN,EXTERNAL,SCRAM"}
	ServerTime  = Capability{Name: "server-time"}
	STS         = Capability{Name: "sts", Value: "port=%s,duration=%.f"}
	// MultiPrefix = Capability{"multi-prefix", ""}
)

func IsRecognized(c string) bool {
	return c == CapNotify.Name || c == EchoMessage.Name || c == MessageTags.Name || c == SASL.Name || c == ServerTime.Name || c == STS.Name
}
