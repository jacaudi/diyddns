package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestCancelled(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"live context, nil error", t.Context(), nil, false},
		{"live context, wrapped canceled", t.Context(), fmt.Errorf("get: %w", context.Canceled), true},
		{"live context, wrapped deadline exceeded", t.Context(), fmt.Errorf("get: %w", context.DeadlineExceeded), true},
		{"cancelled context, unrelated error", cancelled, errors.New("disk on fire"), true},
		{"live context, unrelated error", t.Context(), errors.New("disk on fire"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Cancelled(tt.ctx, tt.err); got != tt.want {
				t.Errorf("Cancelled(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
