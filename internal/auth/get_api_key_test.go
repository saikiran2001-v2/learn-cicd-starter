package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:       "returns api key from valid header",
			authHeader: "ApiKey test-key-123",
			wantKey:    "test-key-123",
			wantErr:    nil,
		},
		{
			name:       "returns error when authorization header is missing",
			authHeader: "",
			wantKey:    "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name:       "returns error when authorization header is malformed",
			authHeader: "Bearer test-key-123",
			wantKey:    "",
			wantErr:    nil,
			wantErrMsg: "malformed authorization header",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.authHeader != "" {
				headers.Set("Authorization", tc.authHeader)
			}

			gotKey, err := GetAPIKey(headers)

			if gotKey != tc.wantKey {
				t.Fatalf("expected key %q, got %q", tc.wantKey, gotKey)
			}

			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
			if tc.wantErrMsg != "" && (err == nil || err.Error() != tc.wantErrMsg) {
				t.Fatalf("expected error message %q, got %v", tc.wantErrMsg, err)
			}
		})
	}
}
