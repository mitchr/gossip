package cap

// A Capabiltity is a capability that the server implements
type Capability string

const (
	MessageTags Capability = "message-tags"
	MultiPrefix Capability = "multi-prefix"
)

// IsValid returns true if c is implemented by the server
func (c Capability) IsValid() bool {
	return c == MessageTags || c == MultiPrefix
}

func StringSlice(c []Capability) []string {
	s := make([]string, len(c))
	for i := 0; i < len(c); i++ {
		s[i] = string(c[i])
	}
	return s
}
