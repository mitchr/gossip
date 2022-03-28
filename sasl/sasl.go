package sasl

import "errors"

// type Credential interface {
// 	Check(username string, key []byte) bool
// }

var (
	ErrInvalidKey error = errors.New("invalid key")
	ErrSaslFail   error = errors.New("sasl failed")
)

type Mechanism interface {
	// Next returns the next challenge to be sent to the client. If both
	// challenge and err are nil, it is assumed that the authentication is
	// completed and successful.
	Next(clientResponse []byte) (challenge []byte, err error)

	// Authn returns the authentication string associate with this
	// specific mechanism instance. It may be unsafe to call Authn before
	// the mechanism has completed.
	Authn() string
}
