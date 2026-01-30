package traefik

import "testing"

func TestExtractHosts(t *testing.T) {
	tests := []struct {
		name     string
		rule     string
		expected []string
	}{
		{
			name:     "single host",
			rule:     "Host(`example.com`)",
			expected: []string{"example.com"},
		},
		{
			name:     "multiple hosts single clause",
			rule:     "Host(`a.example.com`, `b.example.com`)",
			expected: []string{"a.example.com", "b.example.com"},
		},
		{
			name:     "multiple clauses",
			rule:     "Host(`a.com`) || Host(`b.com`)",
			expected: []string{"a.com", "b.com"},
		},
		{
			name:     "mixed rule",
			rule:     "Host(`app.example.com`) && PathPrefix(`/`)",
			expected: []string{"app.example.com"},
		},
		{
			name:     "no host rule",
			rule:     "PathPrefix(`/`)",
			expected: nil,
		},
		{
			name:     "non-backtick host",
			rule:     `Host("example.com")`,
			expected: nil,
		},
		{
			name:     "spacing variance",
			rule:     "Host( `a.com` ,`b.com` )",
			expected: []string{"a.com", "b.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractHosts(tc.rule)
			if len(got) != len(tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					t.Fatalf("expected %v, got %v", tc.expected, got)
				}
			}
		})
	}
}
