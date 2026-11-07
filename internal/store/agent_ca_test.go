package store

import (
	"bytes"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// colInfo is one PRAGMA table_info column: its declared type and NOT NULL flag.
type colInfo struct {
	typ     string
	notNull bool
}

func tableColumns(t *testing.T, s *Store, table string) (names []string, cols map[string]colInfo) {
	t.Helper()
	rows, err := s.DB().QueryContext(t.Context(), `PRAGMA table_info(`+table+`)`)
	if err != nil {
		t.Fatalf("table_info(%s): %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	cols = map[string]colInfo{}
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		names = append(names, name)
		cols[name] = colInfo{typ: typ, notNull: notNull != 0}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info rows: %v", err)
	}
	return names, cols
}

func TestMigration011_Shape(t *testing.T) {
	s, ctx := newTestStore(t)

	_, err := s.DB().ExecContext(ctx,
		`INSERT INTO agent_ca (id, active_der, backup_der, created_at, updated_at) VALUES (2, x'00', x'00', 1, 1)`)
	if err == nil || !strings.Contains(err.Error(), "CHECK") {
		t.Errorf("insert id=2: err = %v, want a CHECK constraint failure", err)
	}

	names, _ := tableColumns(t, s, "agent_ca")
	want := []string{"id", "active_der", "backup_der", "created_at", "updated_at"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("agent_ca columns = %v, want %v", names, want)
	}

	_, dev := tableColumns(t, s, "devices")
	for col, typ := range map[string]string{"cert_serial": "TEXT", "cert_not_after": "INTEGER"} {
		got, ok := dev[col]
		if !ok {
			t.Errorf("devices.%s missing", col)
			continue
		}
		if got.typ != typ || got.notNull {
			t.Errorf("devices.%s = %+v, want nullable %s", col, got, typ)
		}
	}
}

func TestAgentCA_GetEmptyIsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	if _, err := s.AgentCA().Get(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on empty: err = %v, want ErrNotFound", err)
	}
}

func TestAgentCA_InsertThenGet(t *testing.T) {
	s, ctx := newTestStore(t)
	want := AgentCA{ActiveDER: []byte{1, 2, 3}, BackupDER: []byte{4, 5, 6, 7}}

	if err := s.AgentCA().Insert(ctx, want); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	got, err := s.AgentCA().Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.ActiveDER, want.ActiveDER) || !bytes.Equal(got.BackupDER, want.BackupDER) {
		t.Errorf("Get = %+v, want %+v", got, want)
	}
}

func TestAgentCA_InsertTwiceConflicts(t *testing.T) {
	s, ctx := newTestStore(t)
	ca := AgentCA{ActiveDER: []byte{1}, BackupDER: []byte{2}}
	if err := s.AgentCA().Insert(ctx, ca); err != nil {
		t.Fatalf("first Insert: %v", err)
	}
	if err := s.AgentCA().Insert(ctx, ca); !errors.Is(err, ErrConflict) {
		t.Fatalf("second Insert: err = %v, want ErrConflict", err)
	}
}

func TestAgentCA_PromoteWithoutRowIsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	err := s.AgentCA().Promote(ctx, AgentCA{ActiveDER: []byte{1}, BackupDER: []byte{2}})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Promote on empty: err = %v, want ErrNotFound", err)
	}
}

func TestAgentCA_PromoteClearsDeviceCerts(t *testing.T) {
	s, ctx := newTestStore(t)
	a := seedCertDevice(t, ctx, s, "a@example.com", "one")
	b := seedCertDevice(t, ctx, s, "b@example.com", "two")
	for _, id := range []string{a, b} {
		if err := s.Devices().SetCert(ctx, id, "0a1b", 1900000000); err != nil {
			t.Fatalf("SetCert: %v", err)
		}
	}
	if err := s.AgentCA().Insert(ctx, AgentCA{ActiveDER: []byte{1}, BackupDER: []byte{2}}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	next := AgentCA{ActiveDER: []byte{9, 9}, BackupDER: []byte{8, 8}}
	if err := s.AgentCA().Promote(ctx, next); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	got, err := s.AgentCA().Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.ActiveDER, next.ActiveDER) || !bytes.Equal(got.BackupDER, next.BackupDER) {
		t.Errorf("Get after Promote = %+v, want %+v", got, next)
	}
	for _, id := range []string{a, b} {
		d, err := s.Devices().GetByID(ctx, id)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if d.CertSerial != "" || d.CertNotAfter != 0 {
			t.Errorf("device %s cert = (%q, %d), want cleared", id, d.CertSerial, d.CertNotAfter)
		}
	}
}

func TestAgentCA_ResetIsIdempotent(t *testing.T) {
	s, ctx := newTestStore(t)
	id := seedCertDevice(t, ctx, s, "a@example.com", "one")
	if err := s.Devices().SetCert(ctx, id, "0a1b", 1900000000); err != nil {
		t.Fatalf("SetCert: %v", err)
	}
	if err := s.AgentCA().Insert(ctx, AgentCA{ActiveDER: []byte{1}, BackupDER: []byte{2}}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	for i := range 2 {
		if err := s.AgentCA().Reset(ctx); err != nil {
			t.Fatalf("Reset #%d: %v", i+1, err)
		}
	}
	if _, err := s.AgentCA().Get(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Reset: err = %v, want ErrNotFound", err)
	}
	d, err := s.Devices().GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if d.CertSerial != "" || d.CertNotAfter != 0 {
		t.Errorf("device cert = (%q, %d), want cleared", d.CertSerial, d.CertNotAfter)
	}
}
