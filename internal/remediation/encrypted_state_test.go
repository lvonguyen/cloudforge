package remediation

import (
	"encoding/json"
	"testing"
)

// validHexKey is a 32-byte key (64 hex chars) for test use only.
const validHexKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestEncryptedStateStore_RoundTrip(t *testing.T) {
	t.Setenv("AEGIS_STATE_ENCRYPTION_KEY", validHexKey)

	store, err := NewEncryptedStateStore("AEGIS_STATE_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("NewEncryptedStateStore: %v", err)
	}

	original := []byte(`{"finding_id":"F-001","resource_id":"arn:aws:s3:::bucket","pre_state":{"public":true}}`)

	ciphertext, err := store.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	plaintext, err := store.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(plaintext) != string(original) {
		t.Errorf("round-trip mismatch:\n  got:  %s\n  want: %s", plaintext, original)
	}
}

func TestEncryptedStateStore_WrongKey(t *testing.T) {
	t.Setenv("AEGIS_STATE_ENCRYPTION_KEY", validHexKey)
	store1, err := NewEncryptedStateStore("AEGIS_STATE_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("store1: %v", err)
	}

	ciphertext, err := store1.Encrypt([]byte("secret rollback state"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Create second store with a different key
	t.Setenv("AEGIS_STATE_ENCRYPTION_KEY", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	store2, err := NewEncryptedStateStore("AEGIS_STATE_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("store2: %v", err)
	}

	_, err = store2.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key, got nil")
	}
}

func TestEncryptedStateStore_CiphertextNotJSON(t *testing.T) {
	t.Setenv("AEGIS_STATE_ENCRYPTION_KEY", validHexKey)
	store, err := NewEncryptedStateStore("AEGIS_STATE_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("NewEncryptedStateStore: %v", err)
	}

	original := []byte(`{"key":"value","nested":{"a":1}}`)
	ciphertext, err := store.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Ciphertext must not be parseable as JSON — it's opaque binary.
	var probe map[string]any
	if err := json.Unmarshal(ciphertext, &probe); err == nil {
		t.Error("ciphertext was parseable as JSON — encryption is not working")
	}
}

func TestEncryptedStateStore_MissingEnvVar(t *testing.T) {
	t.Setenv("AEGIS_STATE_ENCRYPTION_KEY", "")
	_, err := NewEncryptedStateStore("AEGIS_STATE_ENCRYPTION_KEY")
	if err == nil {
		t.Fatal("expected error for missing env var, got nil")
	}
}

func TestEncryptedStateStore_InvalidHex(t *testing.T) {
	t.Setenv("AEGIS_STATE_ENCRYPTION_KEY", "not-valid-hex")
	_, err := NewEncryptedStateStore("AEGIS_STATE_ENCRYPTION_KEY")
	if err == nil {
		t.Fatal("expected error for invalid hex, got nil")
	}
}

func TestEncryptedStateStore_WrongKeyLength(t *testing.T) {
	// 16-byte key (32 hex chars) — valid AES-128 but not AES-256
	t.Setenv("AEGIS_STATE_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")
	_, err := NewEncryptedStateStore("AEGIS_STATE_ENCRYPTION_KEY")
	if err == nil {
		t.Fatal("expected error for 16-byte key, got nil")
	}
}

func TestEncryptedStateStore_TruncatedCiphertext(t *testing.T) {
	t.Setenv("AEGIS_STATE_ENCRYPTION_KEY", validHexKey)
	store, err := NewEncryptedStateStore("AEGIS_STATE_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("NewEncryptedStateStore: %v", err)
	}

	// Less than nonce size (12 bytes)
	_, err = store.Decrypt([]byte("short"))
	if err == nil {
		t.Fatal("expected error for truncated ciphertext, got nil")
	}
}

func TestEncryptedStateStore_UniqueNonce(t *testing.T) {
	t.Setenv("AEGIS_STATE_ENCRYPTION_KEY", validHexKey)
	store, err := NewEncryptedStateStore("AEGIS_STATE_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("NewEncryptedStateStore: %v", err)
	}

	// Encrypt the same plaintext twice — ciphertexts must differ due to random nonces.
	ct1, err := store.Encrypt([]byte("same input"))
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	ct2, err := store.Encrypt([]byte("same input"))
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	if string(ct1) == string(ct2) {
		t.Error("two encryptions of the same plaintext produced identical ciphertext — nonce reuse")
	}
}
