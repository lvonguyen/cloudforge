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

func TestAttackPathWarmupEnabledForCorpus(t *testing.T) {
	t.Setenv("ATTACK_PATH_WARMUP_MAX_FINDINGS", "")
	if !attackPathWarmupEnabledForCorpus(defaultAttackPathWarmupMaxFindings) {
		t.Fatal("expected attack path warmup enabled at default threshold")
	}
	if attackPathWarmupEnabledForCorpus(defaultAttackPathWarmupMaxFindings + 1) {
		t.Fatal("expected attack path warmup disabled above default threshold")
	}
}

func TestSecgraphFullSyncEnabledForCorpus(t *testing.T) {
	t.Setenv("SECGRAPH_FULL_SYNC_MAX_FINDINGS", "")
	if !secgraphFullSyncEnabledForCorpus(defaultSecgraphFullSyncMaxFindings) {
		t.Fatal("expected secgraph full sync enabled at default threshold")
	}
	if secgraphFullSyncEnabledForCorpus(defaultSecgraphFullSyncMaxFindings + 1) {
		t.Fatal("expected secgraph full sync disabled above default threshold")
	}
}
