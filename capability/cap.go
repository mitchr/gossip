package capability

// A Capabiltity is a capability that the server implements
type Cap struct {
	Name, Value string
}

func (c Cap) String() string { return c.Name }

var (
	AwayNotify  = Cap{Name: "away-notify"}
	CapNotify   = Cap{Name: "cap-notify"}
	EchoMessage = Cap{Name: "echo-message"}
	MessageTags = Cap{Name: "message-tags"}
	SASL        = Cap{Name: "sasl", Value: "PLAIN,EXTERNAL,SCRAM"}
	ServerTime  = Cap{Name: "server-time"}
	Setname     = Cap{Name: "setname"}
	STS         = Cap{Name: "sts", Value: "port=%s,duration=%.f"}
	// MultiPrefix = Capability{"multi-prefix", ""}
)
