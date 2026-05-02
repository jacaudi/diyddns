package store

import "time"

// NowUnix returns the current time as unix seconds (UTC). All persisted
// timestamps in this package are unix seconds.
func NowUnix() int64 {
	return time.Now().Unix()
}

// UnixToTime converts a stored unix-seconds value to a UTC time.Time. The
// inverse of NowUnix() / time.Now().Unix() round-trips at second precision.
func UnixToTime(sec int64) time.Time {
	return time.Unix(sec, 0).UTC()
}
