package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveThenLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "credentials.json")
	want := Credentials{ServerURL: "https://ddns.example.com", DeviceID: "dev_123", Secret: "c2VjcmV0"}
	if err := Save(path, want, false); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Errorf("round trip: got %+v want %+v", got, want)
	}
}

func TestSavePermissions0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix perms")
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := Save(path, Credentials{DeviceID: "d"}, false); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestSaveRefusesExistingWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := Save(path, Credentials{DeviceID: "first"}, false); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	err := Save(path, Credentials{DeviceID: "second"}, false)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second Save err = %v, want ErrExists", err)
	}
	got, _ := Load(path)
	if got.DeviceID != "first" {
		t.Errorf("file was clobbered: %q", got.DeviceID)
	}
}

func TestSaveForceOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	_ = Save(path, Credentials{DeviceID: "first"}, false)
	if err := Save(path, Credentials{DeviceID: "second"}, true); err != nil {
		t.Fatalf("force Save: %v", err)
	}
	got, _ := Load(path)
	if got.DeviceID != "second" {
		t.Errorf("force did not overwrite: %q", got.DeviceID)
	}
}

func TestLoadMissingReturnsErrNotFound(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
