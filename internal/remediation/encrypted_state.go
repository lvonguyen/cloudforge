package remediation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// EncryptedStateStore wraps AES-256-GCM encryption for remediation rollback state.
// Key material is read from an environment variable containing a 32-byte hex string.
type EncryptedStateStore struct {
	aead cipher.AEAD
}

// NewEncryptedStateStore reads a 32-byte hex key from the named env var
// and returns an EncryptedStateStore backed by AES-256-GCM.
func NewEncryptedStateStore(envVar string) (*EncryptedStateStore, error) {
	hexKey := os.Getenv(envVar)
	if hexKey == "" {
		return nil, fmt.Errorf("encryption key env var %s is not set", envVar)
	}

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decoding hex key from %s: %w", envVar, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes (got %d)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	return &EncryptedStateStore{aead: aead}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a random 12-byte nonce.
// The nonce is prepended to the returned ciphertext: [nonce (12B) || ciphertext || tag (16B)].
func (s *EncryptedStateStore) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize()) // 12 bytes for GCM
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext produced by Encrypt.
// It expects the 12-byte nonce prepended to the ciphertext.
func (s *EncryptedStateStore) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := s.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short (got %d bytes, need at least %d)", len(ciphertext), nonceSize)
	}

	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]

	plaintext, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting state: %w", err)
	}
	return plaintext, nil
}
