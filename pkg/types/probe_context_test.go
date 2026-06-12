package types

import "testing"

func TestExtractedContext_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ec      *ExtractedContext
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil context",
			ec:      nil,
			wantErr: true,
			errMsg:  "nil",
		},
		{
			name:    "wrong version",
			ec:      &ExtractedContext{Version: 2, SystemPrompt: "test"},
			wantErr: true,
			errMsg:  "unsupported context version",
		},
		{
			name:    "empty context",
			ec:      &ExtractedContext{Version: 1},
			wantErr: true,
			errMsg:  "context file is empty",
		},
		{
			name: "tool without name",
			ec: &ExtractedContext{
				Version: 1,
				Tools:   []ToolSchema{{Description: "no name"}},
			},
			wantErr: true,
			errMsg:  "tool at index 0 has no name",
		},
		{
			name: "valid with system prompt only",
			ec: &ExtractedContext{
				Version:      1,
				SystemPrompt: "You are a helpful assistant",
			},
			wantErr: false,
		},
		{
			name: "valid with tools only",
			ec: &ExtractedContext{
				Version: 1,
				Tools:   []ToolSchema{{Name: "get_order"}},
			},
			wantErr: false,
		},
		{
			name: "valid with identity only",
			ec: &ExtractedContext{
				Version:  1,
				Identity: IdentityContext{UserID: "user_123"},
			},
			wantErr: false,
		},
		{
			name: "valid with tenant only",
			ec: &ExtractedContext{
				Version:  1,
				Identity: IdentityContext{Tenant: "acme-corp"},
			},
			wantErr: false,
		},
		{
			name: "valid full context",
			ec: &ExtractedContext{
				Version:      1,
				SystemPrompt: "You are a support agent",
				Tools: []ToolSchema{
					{Name: "get_order", Parameters: map[string]string{"order_id": "string"}},
				},
				Identity:   IdentityContext{UserID: "u1", Tenant: "t1", Role: "admin"},
				Confidence: 0.85,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ec.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %q, want containing %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
