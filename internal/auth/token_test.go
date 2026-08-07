package auth

import "testing"

func TestHashToken_Deterministic(t *testing.T) {
	a := HashToken("abc123")
	b := HashToken("abc123")
	if a != b {
		t.Fatalf("HashToken must be deterministic: %q != %q", a, b)
	}
}

func TestHashToken_DifferentTokensDifferentHashes(t *testing.T) {
	a := HashToken("token-one")
	b := HashToken("token-two")
	if a == b {
		t.Fatal("HashToken: distinct tokens produced the same hash")
	}
}

func TestVerifyToken_RoundTrip(t *testing.T) {
	hash := HashToken("correct-token")
	if !VerifyToken(hash, "correct-token") {
		t.Fatal("VerifyToken: valid token rejected")
	}
}

func TestVerifyToken_WrongTokenRejected(t *testing.T) {
	hash := HashToken("correct-token")
	if VerifyToken(hash, "wrong-token") {
		t.Fatal("VerifyToken: wrong token accepted")
	}
}
