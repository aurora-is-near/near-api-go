package utils

import (
	"fmt"
	"time"
)

// GetResult is the function type used for ExponentialBackoff.
type GetResult func() ([]byte, error)

// ExponentialBackoff implements an exponential backoff strategy for calling
// function fn.
func ExponentialBackoff(
	startWaitTime, retryNumber int,
	waitBackoff float64,
	fn GetResult,
) ([]byte, error) {
	waitTime := startWaitTime
	for i := 0; i < retryNumber; i++ {
		buf, err := fn()
		if err == nil {
			return buf, nil
		}
		// print error and continue
		fmt.Println(err)

		time.Sleep(time.Duration(waitTime) * time.Millisecond)
		waitTime = int(float64(waitTime) * waitBackoff)
	}
	return nil, ErrRetriesExceeded
}
