package near

import (
	"errors"
)

// ErrNotObject is returned if a result is not an object, but should be.
var ErrNotObject = errors.New("near: JSON-RPC result is not an object")

// ErrNotString is returned if a result is not a string, but should be.
var ErrNotString = errors.New("near: JSON-RPC result is not a string")
