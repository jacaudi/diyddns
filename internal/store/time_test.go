package store

import (
	"testing"
	"time"
)

func TestNowUnixIsCurrentSecond(t *testing.T) {
	before := time.Now().Unix()
	got := NowUnix()
	after := time.Now().Unix()
	if got < before || got > after {
		t.Fatalf("NowUnix()=%d not within [%d,%d]", got, before, after)
	}
}

func TestUnixToTime(t *testing.T) {
	now := time.Now().Truncate(time.Second).UTC()
	got := UnixToTime(now.Unix())
	if !got.Equal(now) {
		t.Fatalf("UnixToTime round-trip: got %v, want %v", got, now)
	}
}
