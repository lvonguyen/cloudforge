package webhooks

import "testing"

func FuzzValidateWebhookURL(f *testing.F) {
	for _, seed := range []string{
		"https://example.com/hook",
		"http://example.com/hook",
		"https://localhost/hook",
		"https://localhost./hook",
		"https://api.localhost/hook",
		"https://127.0.0.1/hook",
		"https://169.254.169.254/latest/meta-data",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		err := validateWebhookURL(raw)
		if err == nil {
			if err2 := validateWebhookURL(raw); err2 != nil {
				t.Fatalf("validateWebhookURL is not stable for %q: second error %v", raw, err2)
			}
			return
		}

		if err2 := validateWebhookURL(raw); err2 == nil {
			t.Fatalf("validateWebhookURL is not stable for %q: first error %v, second nil", raw, err)
		}
	})
}
