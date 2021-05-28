package utils

import (
	"errors"
)

// ErrRetriesExceeded if the maximum number of retry attempts have been exceeded for request.
var ErrRetriesExceeded = errors.New("utils: exceeded retry attempts for request")
