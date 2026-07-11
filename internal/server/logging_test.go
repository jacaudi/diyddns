package server_test

import (
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.LoggingSection
		wantErr bool
	}{
		{"json stderr info", config.LoggingSection{Level: "info", Format: "json", Output: "stderr"}, false},
		{"text stdout debug", config.LoggingSection{Level: "debug", Format: "text", Output: "stdout"}, false},
		{"bad level", config.LoggingSection{Level: "loud", Format: "json", Output: "stderr"}, true},
		{"bad format", config.LoggingSection{Level: "info", Format: "xml", Output: "stderr"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := server.NewLogger(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}
			if log == nil {
				t.Fatal("nil logger")
			}
		})
	}
}
