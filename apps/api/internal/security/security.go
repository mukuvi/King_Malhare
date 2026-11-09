package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

var ErrInvalidHash = errors.New("invalid password hash")

func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		// Support legacy bcrypt hashes if they ever exist, without weakening new hashes.
		if strings.HasPrefix(encoded, "$2") {
			return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password)) == nil
		}
		return false
	}
	var memory uint32
	var iter uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iter, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iter, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

var passwordEmailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$`)

func ValidatePassword(pw string) error {
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(pw) > 128 {
		return errors.New("password must be at most 128 characters")
	}
	var upper, lower, digit bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		}
	}
	if !upper || !lower || !digit {
		return errors.New("password must include upper case, lower case and a number")
	}
	return nil
}

func ValidEmail(email string) bool {
	return len(email) <= 254 && passwordEmailRe.MatchString(email)
}

var freeEmailDomains = map[string]struct{}{
	"gmail.com": {}, "googlemail.com": {}, "yahoo.com": {}, "yahoo.co.uk": {},
	"outlook.com": {}, "hotmail.com": {}, "live.com": {}, "msn.com": {},
	"icloud.com": {}, "me.com": {}, "aol.com": {}, "proton.me": {},
	"protonmail.com": {}, "pm.me": {}, "gmx.com": {}, "gmx.net": {},
	"mail.com": {}, "yandex.com": {}, "yandex.ru": {}, "zoho.com": {},
	"tutanota.com": {}, "tuta.io": {}, "fastmail.com": {}, "hey.com": {},
}

// IsFreeEmailDomain reports whether the address belongs to a consumer mailbox
// provider. Organization signup requires a domain the organization controls.
func IsFreeEmailDomain(email string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	_, ok := freeEmailDomains[strings.ToLower(email[at+1:])]
	return ok
}

func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func HashToken(pepper, token string) []byte {
	sum := sha256.Sum256([]byte(pepper + ":" + token))
	return sum[:]
}

func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// CredentialCipher encrypts cloud/API secrets with AES-256-GCM.
type CredentialCipher struct {
	aead cipher.AEAD
}

func NewCredentialCipher(hexKey string) (*CredentialCipher, error) {
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("credential encryption key must be 64 hex characters")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &CredentialCipher{aead: aead}, nil
}

func (c *CredentialCipher) Encrypt(plaintext []byte, aad string) ([]byte, []byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	out := c.aead.Seal(nil, nonce, plaintext, []byte(aad))
	return out, nonce, nil
}

func (c *CredentialCipher) Decrypt(ciphertext, nonce []byte, aad string) ([]byte, error) {
	return c.aead.Open(nil, nonce, ciphertext, []byte(aad))
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func Slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) < 2 {
		s = "org-" + s
	}
	if len(s) > 60 {
		s = strings.Trim(s[:60], "-")
	}
	return s
}

func MaskSecret(s string) string {
	if len(s) <= 8 {
		return "••••••••"
	}
	return s[:4] + "••••••••" + s[len(s)-4:]
}

func SessionExpiry(now time.Time, ttl time.Duration) time.Time { return now.Add(ttl) }
