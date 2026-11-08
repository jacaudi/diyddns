package store

import "time"

// NowUnix returns the current time as unix seconds (UTC). All persisted
// timestamps in this package are unix seconds.
func NowUnix() int64 {
	return time.Now().Unix()
}
