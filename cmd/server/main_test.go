package main

import "testing"

func TestLargeCorpusWarmupEnabled(t *testing.T) {
	t.Setenv("LARGE_CORPUS_WARMUP_ENABLED", "")
	if largeCorpusWarmupEnabled() {
		t.Fatal("expected warmup to be disabled by default")
	}

	t.Setenv("LARGE_CORPUS_WARMUP_ENABLED", "true")
	if !largeCorpusWarmupEnabled() {
		t.Fatal("expected warmup to be enabled when env is true")
	}
}

func TestLargeCorpusSecgraphSyncEnabled(t *testing.T) {
	t.Setenv("LARGE_CORPUS_SECGRAPH_SYNC_ENABLED", "")
	if largeCorpusSecgraphSyncEnabled() {
		t.Fatal("expected secgraph sync to be disabled by default")
	}

	t.Setenv("LARGE_CORPUS_SECGRAPH_SYNC_ENABLED", "true")
	if !largeCorpusSecgraphSyncEnabled() {
		t.Fatal("expected secgraph sync to be enabled when env is true")
	}
}
