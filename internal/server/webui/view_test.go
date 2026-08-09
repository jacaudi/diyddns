package webui

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

func TestDeviceStatus(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()

	tests := []struct {
		name string
		dev  store.Device
		want Status
	}{
		{"disabled beats everything", store.Device{Disabled: true, LastSeenAt: now.Unix()}, StatusDisabled},
		{"disabled beats never-seen", store.Device{Disabled: true, LastSeenAt: 0}, StatusDisabled},
		{"never reported", store.Device{LastSeenAt: 0}, StatusNeverSeen},
		{"just now", store.Device{LastSeenAt: now.Unix()}, StatusOnline},
		{"one second inside the window", store.Device{LastSeenAt: now.Add(-staleAfter + time.Second).Unix()}, StatusOnline},
		{"exactly at the threshold is still online", store.Device{LastSeenAt: now.Add(-staleAfter).Unix()}, StatusOnline},
		{"one second past the threshold", store.Device{LastSeenAt: now.Add(-staleAfter - time.Second).Unix()}, StatusStale},
		{"long stale", store.Device{LastSeenAt: now.Add(-72 * time.Hour).Unix()}, StatusStale},
		{"clock skew: seen in the future reads online", store.Device{LastSeenAt: now.Add(time.Minute).Unix()}, StatusOnline},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := deviceStatus(tt.dev, now); got != tt.want {
				t.Errorf("deviceStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRelTime(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 14, 41, 0, 0, time.UTC)

	tests := []struct {
		name string
		at   time.Time
		want string
	}{
		{"never", time.Unix(0, 0), "never"},
		{"seconds", now.Add(-42 * time.Second), "42s ago"},
		{"minutes", now.Add(-3 * time.Minute), "3m ago"},
		{"hours", now.Add(-6 * time.Hour), "6h ago"},
		{"yesterday", now.Add(-26 * time.Hour), "Yesterday"},
		{"older falls back to a date", now.Add(-8 * 24 * time.Hour), "2026-07-12"},
		{"future clamps to just now", now.Add(time.Minute), "just now"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			at := tt.at.Unix()
			if tt.name == "never" {
				at = 0
			}
			if got := relTime(at, now); got != tt.want {
				t.Errorf("relTime() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfgBase string
		tls     bool
		xfProto string
		want    string
	}{
		{"configured base wins", "https://ddns.example.com", false, "", "https://ddns.example.com"},
		{"configured base keeps winning over TLS", "https://ddns.example.com", true, "", "https://ddns.example.com"},
		{"trailing slash is trimmed", "https://ddns.example.com/", false, "", "https://ddns.example.com"},
		{"unset falls back to the request host", "", false, "", "http://ddns.test"},
		{"unset with TLS uses https", "", true, "", "https://ddns.test"},
		{"X-Forwarded-Proto is never trusted", "", false, "https", "http://ddns.test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "http://ddns.test/devices", nil)
			req.Host = "ddns.test"
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tt.xfProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xfProto)
			}
			var cfg config.Server
			cfg.Server.BaseURL = tt.cfgBase

			if got := baseURL(cfg, req); got != tt.want {
				t.Errorf("baseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInitials(t *testing.T) {
	t.Parallel()

	tests := []struct{ email, want string }{
		{"jane@example.com", "JA"},
		{"j@example.com", "J"},
		{"", "?"},
		{"@example.com", "?"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			t.Parallel()
			if got := initials(tt.email); got != tt.want {
				t.Errorf("initials(%q) = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}
