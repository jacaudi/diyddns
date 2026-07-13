package shared

import "testing"

func TestBodyHashHex_EmptyIsSHA256OfEmpty(t *testing.T) {
	// SHA256("") well-known value.
	if got := BodyHashHex(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty body hash = %q", got)
	}
}

func TestCanonicalRequest_NewlineJoinedLF(t *testing.T) {
	got := CanonicalRequest("POST", "/agent/v1/checkin", "1720000000", "nonce123", "abcd")
	want := "POST\n/agent/v1/checkin\n1720000000\nnonce123\nabcd"
	if got != want {
		t.Fatalf("canonical =\n%q\nwant\n%q", got, want)
	}
}

func TestSign_KnownVector(t *testing.T) {
	// HMAC-SHA256 of "msg" under key "key", lowercase hex.
	if got := Sign([]byte("key"), "msg"); got != "2d93cbc1be167bcb1637a4a23cbff01a7878f0c50ee833954ea5221bb1b8c628" {
		t.Fatalf("sign = %q", got)
	}
}

func TestSign_Deterministic(t *testing.T) {
	a := Sign([]byte("s"), CanonicalRequest("GET", "/agent/v1/self", "1", "n", BodyHashHex(nil)))
	b := Sign([]byte("s"), CanonicalRequest("GET", "/agent/v1/self", "1", "n", BodyHashHex(nil)))
	if a != b {
		t.Fatal("Sign not deterministic")
	}
}
