package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

// TestSaveConcurrentNoForceExactlyOneWins is the regression test for #21: two
// concurrent Save(path, _, false) calls raced os.Stat + os.Rename, so both
// could pass the initial existence check and the second Rename would silently
// clobber the first — violating the documented "refuse to overwrite" contract.
// With os.Link on the non-force path, Link fails atomically with EEXIST for
// whichever call loses the race, so exactly one write survives and it is
// never partially overwritten by the other.
func TestSaveConcurrentNoForceExactlyOneWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	const n = 50
	results := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- Save(path, Credentials{DeviceID: fmt.Sprintf("racer-%d", i)}, false)
		}(i)
	}
	wg.Wait()
	close(results)

	wins, losses := 0, 0
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrExists):
			losses++
		default:
			t.Fatalf("unexpected error from a racing Save: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("wins = %d, want exactly 1 (got %d losses) — non-force Save is not race-free", wins, losses)
	}
	if losses != n-1 {
		t.Fatalf("losses = %d, want %d", losses, n-1)
	}

	// The surviving file must be intact, valid JSON belonging to exactly one
	// of the racers — not a torn/partial write from two writers colliding.
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load after race: %v", err)
	}
	if got.DeviceID == "" {
		t.Errorf("surviving credentials file has empty DeviceID — looks torn: %+v", got)
	}

	// No leaked .tmp.* files from either the winner or any loser.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("leaked tmp file after race: %s", e.Name())
		}
	}
}

// TestSaveUniqueTmpNames is a narrower unit check that randSuffix() actually
// varies -- a fixed suffix would silently reintroduce the tmp-file half of #21
// even with the os.Link fix in place.
func TestSaveUniqueTmpNames(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		s := randSuffix()
		if seen[s] {
			t.Fatalf("randSuffix produced a duplicate after %d calls: %q", i, s)
		}
		seen[s] = true
	}
}
