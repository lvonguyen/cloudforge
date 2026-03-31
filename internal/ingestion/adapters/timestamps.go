package adapters

import (
	"strings"
	"time"
)

var unknownFindingTime = time.Unix(0, 0).UTC()

type timestampCandidate struct {
	name  string
	value string
}

func parseFindingTimestamp(candidates ...timestampCandidate) (time.Time, map[string]string) {
	metadata := make(map[string]string)

	for _, candidate := range candidates {
		raw := strings.TrimSpace(candidate.value)
		if raw == "" {
			continue
		}

		metadata["timestamp_raw_"+candidate.name] = raw

		parsed, err := time.Parse(time.RFC3339, raw)
		if err == nil {
			metadata["timestamp_source"] = candidate.name
			return parsed.UTC(), metadata
		}

		metadata["timestamp_parse_error_"+candidate.name] = err.Error()
	}

	metadata["timestamp_source"] = "fallback"
	metadata["timestamp_fallback"] = "unix_epoch"
	return unknownFindingTime, metadata
}

func mergeRawData(base, extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		base = make(map[string]string, len(extra))
	}
	for key, value := range extra {
		base[key] = value
	}
	return base
}
