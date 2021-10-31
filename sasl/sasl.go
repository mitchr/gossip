package sasl

import "errors"

// type Credential interface {
// 	Check(username string, key []byte) bool
// }

var (
	ErrInvalidKey error = errors.New("invalid key")
	ErrSaslFail   error = errors.New("sasl failed")
	ErrDone       error = errors.New("mechanism done")
)

type Mechanism interface {
	Next(clientResponse []byte) (challenge []byte, err error)
}
