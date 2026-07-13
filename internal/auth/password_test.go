package auth

import "testing"

func testParams() Argon2Params { return Argon2Params{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1} } // fast for tests

func TestHashVerifyPassword_RoundTrip(t *testing.T) {
	enc, err := HashPassword("correct horse battery staple", testParams())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(enc, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("valid password rejected")
	}
}

func TestVerifyPassword_WrongIsFalse(t *testing.T) {
	enc, _ := HashPassword("hunter2hunter2", testParams())
	ok, err := VerifyPassword(enc, "wrong-password")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong password accepted")
	}
}

func TestHashPassword_SaltedDistinct(t *testing.T) {
	a, _ := HashPassword("samepassword", testParams())
	b, _ := HashPassword("samepassword", testParams())
	if a == b {
		t.Fatal("hashes must differ (random salt)")
	}
}
