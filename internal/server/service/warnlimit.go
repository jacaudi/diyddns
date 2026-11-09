package service

import (
	"sync"
	"time"
)

// warnWindow is how long a device's WARN of one kind stays suppressed.
const warnWindow = time.Hour

// warnLimiter lets a WARN through at most once per device per warnWindow. State
// is in memory and resets on restart. Check-ins run concurrently, so the map is
// guarded by mu. The zero value is ready to use.
//
// ponytail: entries are never evicted; the map is bounded by the number of
// devices that ever hit the WARN. Evict stale entries if that count matters.
type warnLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// allow reports whether the WARN for deviceID may be logged at now, and if so
// starts a new window.
func (l *warnLimiter) allow(deviceID string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[deviceID]; ok && now.Sub(t) < warnWindow {
		return false
	}
	if l.last == nil {
		l.last = make(map[string]time.Time)
	}
	l.last[deviceID] = now
	return true
}
