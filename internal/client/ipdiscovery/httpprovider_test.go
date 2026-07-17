package ipdiscovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPProvider_ParseAndFamilyValidate(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		family Family
		wantOK bool
	}{
		{"plain v4", "203.0.113.7", FamilyV4, true},
		{"v4 with trailing newline", "203.0.113.7\n", FamilyV4, true},
		{"wrong family: v6 body for v4 provider", "2001:db8::1", FamilyV4, false},
		{"garbage", "not-an-ip", FamilyV4, false},
		{"plain v6", "2001:db8::1", FamilyV6, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			// Use the default client (not family-locked) so httptest's 127.0.0.1
			// is reachable; family validation is on the PARSED address, not the dial.
			p := NewHTTPProvider(srv.URL, tt.family, srv.Client())
			addr, err := p.Lookup(context.Background())
			if tt.wantOK {
				if err != nil {
					t.Fatalf("Lookup err = %v, want nil", err)
				}
				if !addr.IsValid() {
					t.Errorf("addr invalid")
				}
			} else if err == nil {
				t.Errorf("Lookup err = nil, want error for %q", tt.body)
			}
		})
	}
}

func TestDefaultProviders_Shape(t *testing.T) {
	if got := len(DefaultProvidersV4()); got != 3 {
		t.Errorf("DefaultProvidersV4 count = %d, want 3", got)
	}
	if got := len(DefaultProvidersV6()); got != 3 {
		t.Errorf("DefaultProvidersV6 count = %d, want 3", got)
	}
	if got := len(ProvidersFromURLs([]string{"https://a", "https://b"}, FamilyV4)); got != 2 {
		t.Errorf("ProvidersFromURLs count = %d, want 2", got)
	}
}
