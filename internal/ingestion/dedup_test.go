package ingestion

import (
	"sync"
	"testing"
	"time"
)

func TestGenerateDedupKey_Deterministic(t *testing.T) {
	k1 := GenerateDedupKey("aws-securityhub", "SH-001", "arn:aws:s3:::bucket", "123456789012")
	k2 := GenerateDedupKey("aws-securityhub", "SH-001", "arn:aws:s3:::bucket", "123456789012")
	if k1 != k2 {
		t.Errorf("same inputs produced different keys: %s vs %s", k1, k2)
	}
}

func TestGenerateDedupKey_DifferentInputs(t *testing.T) {
	k1 := GenerateDedupKey("aws-securityhub", "SH-001", "arn:aws:s3:::bucket-a", "123456789012")
	k2 := GenerateDedupKey("aws-securityhub", "SH-001", "arn:aws:s3:::bucket-b", "123456789012")
	if k1 == k2 {
		t.Error("different inputs produced the same key")
	}
}

func TestGenerateDedupKey_NoDelimiterCollision(t *testing.T) {
	// Without a null delimiter, these would concatenate to the same byte string.
	k1 := GenerateDedupKey("ab", "cd", "e", "f")
	k2 := GenerateDedupKey("a", "bcd", "e", "f")
	if k1 == k2 {
		t.Error("delimiter collision: different field splits produced the same key")
	}
}

func TestDedupCache_InsertAndDuplicate(t *testing.T) {
	cache := NewDedupCache(24 * time.Hour)
	key := GenerateDedupKey("src", "SF-1", "res-1", "acct-1")

	dup, entry := cache.CheckOrInsert(key, "F-001")
	if dup {
		t.Fatal("first insert should not be duplicate")
	}
	if entry.FindingID != "F-001" {
		t.Errorf("findingID = %q, want %q", entry.FindingID, "F-001")
	}

	dup2, entry2 := cache.CheckOrInsert(key, "F-002")
	if !dup2 {
		t.Fatal("second insert with same key should be duplicate")
	}
	if entry2.FindingID != "F-001" {
		t.Errorf("duplicate entry findingID = %q, want original %q", entry2.FindingID, "F-001")
	}
}

func TestDedupCache_TTLExpiry(t *testing.T) {
	cache := NewDedupCache(1 * time.Millisecond)
	key := "test-key"

	cache.CheckOrInsert(key, "F-001")
	time.Sleep(5 * time.Millisecond)

	dup, entry := cache.CheckOrInsert(key, "F-002")
	if dup {
		t.Fatal("entry should have expired")
	}
	if entry.FindingID != "F-002" {
		t.Errorf("findingID = %q, want %q (re-inserted after expiry)", entry.FindingID, "F-002")
	}
}

func TestDedupCache_ConcurrentAccess(t *testing.T) {
	cache := NewDedupCache(24 * time.Hour)

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := GenerateDedupKey("src", "SF-1", "res-1", "acct-1")
			cache.CheckOrInsert(key, "F-001")
		}(i)
	}
	wg.Wait()
}
