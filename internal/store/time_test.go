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
