package security

import (
	"strings"
	"testing"
)

func TestPasswordHashingAndVerification(t *testing.T) {
	pw := "CorrectHorse9Battery"
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("expected argon2id hash, got %s", hash[:12])
	}
	if !VerifyPassword(pw, hash) {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword("WrongHorse9Battery", hash) {
		t.Fatal("incorrect password accepted")
	}
	if !VerifyPassword(pw, hashOnce(t, pw)) {
		t.Fatal("second hash should verify")
	}
}

func hashOnce(t *testing.T, pw string) string {
	t.Helper()
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestPasswordPolicy(t *testing.T) {
	if err := ValidatePassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := ValidatePassword("alllowercase123"); err == nil {
		t.Fatal("password without upper case accepted")
	}
	if err := ValidatePassword("ALLUPPERCASE123"); err == nil {
		t.Fatal("password without lower case accepted")
	}
	if err := ValidatePassword("NoDigitsHereAtAll"); err == nil {
		t.Fatal("password without digit accepted")
	}
	if err := ValidatePassword("ValidPassword123"); err != nil {
		t.Fatalf("valid password rejected: %v", err)
	}
}

func TestCredentialCipherRoundTrip(t *testing.T) {
	cipher, err := NewCredentialCipher("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"access_key_id":"AKIAEXAMPLE","secret_access_key":"secret"}`)
	enc, nonce, err := cipher.Encrypt(plain, "org:connection")
	if err != nil {
		t.Fatal(err)
	}
	if string(enc) == string(plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	out, err := cipher.Decrypt(enc, nonce, "org:connection")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plain) {
		t.Fatalf("round trip mismatch: %s", out)
	}
	if _, err := cipher.Decrypt(enc, nonce, "wrong-aad"); err == nil {
		t.Fatal("decryption with wrong AAD succeeded")
	}
}

func TestTokenHashingIsStableAndPeppered(t *testing.T) {
	a := HashToken("pepper-a", "token")
	b := HashToken("pepper-a", "token")
	c := HashToken("pepper-b", "token")
	if string(a) != string(b) {
		t.Fatal("hash is not stable")
	}
	if string(a) == string(c) {
		t.Fatal("pepper is not applied")
	}
	if ConstantTimeEqual("abc", "abc") != true || ConstantTimeEqual("abc", "abd") != false {
		t.Fatal("constant time comparison incorrect")
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Acme Security":       "acme-security",
		"  King   Malhare  ":  "king-malhare",
		"Ünïcode & Symbols!!": "n-code-symbols",
	}
	for input, want := range cases {
		if got := Slugify(input); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", input, got, want)
		}
	}
}
