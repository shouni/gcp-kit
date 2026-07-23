package auth

import "testing"

func TestNewHandlerValidatesConfig(t *testing.T) {
	t.Parallel()

	valid := Config{
		ClientID:          "client-id",
		ClientSecret:      "client-secret",
		RedirectURL:       "https://example.com/auth/callback",
		SessionAuthKey:    "1234567890123456",
		SessionEncryptKey: "1234567890123456",
		SessionName:       "session",
	}

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "missing client id",
			cfg: Config{
				ClientSecret:      valid.ClientSecret,
				RedirectURL:       valid.RedirectURL,
				SessionAuthKey:    valid.SessionAuthKey,
				SessionEncryptKey: valid.SessionEncryptKey,
				SessionName:       valid.SessionName,
			},
		},
		{
			name: "relative redirect url",
			cfg: Config{
				ClientID:          valid.ClientID,
				ClientSecret:      valid.ClientSecret,
				RedirectURL:       "/auth/callback",
				SessionAuthKey:    valid.SessionAuthKey,
				SessionEncryptKey: valid.SessionEncryptKey,
				SessionName:       valid.SessionName,
			},
		},
		{
			name: "missing session name",
			cfg: Config{
				ClientID:          valid.ClientID,
				ClientSecret:      valid.ClientSecret,
				RedirectURL:       valid.RedirectURL,
				SessionAuthKey:    valid.SessionAuthKey,
				SessionEncryptKey: valid.SessionEncryptKey,
			},
		},
	}

	if _, err := NewHandler(valid); err != nil {
		t.Fatalf("NewHandler(valid) returned error: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewHandler(tt.cfg); err == nil {
				t.Fatalf("NewHandler() error = nil, want error")
			}
		})
	}
}
