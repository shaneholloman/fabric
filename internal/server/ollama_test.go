package restapi

import (
	"testing"
)

func TestBuildFabricChatURL(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		want    string
		wantErr bool
	}{
		{
			name:    "empty address",
			addr:    "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "valid http URL",
			addr:    "http://localhost:8080",
			want:    "http://localhost:8080",
			wantErr: false,
		},
		{
			name:    "valid https URL",
			addr:    "https://api.example.com",
			want:    "https://api.example.com",
			wantErr: false,
		},
		{
			name:    "http URL with trailing slash",
			addr:    "http://localhost:8080/",
			want:    "http://localhost:8080",
			wantErr: false,
		},
		{
			name:    "malformed URL - missing host",
			addr:    "http://",
			want:    "",
			wantErr: true,
		},
		{
			name:    "malformed URL - port only with http",
			addr:    "https://:8080",
			want:    "",
			wantErr: true,
		},
		{
			name:    "colon-prefixed port",
			addr:    ":8080",
			want:    "http://127.0.0.1:8080",
			wantErr: false,
		},
		{
			name:    "bare host:port",
			addr:    "localhost:8080",
			want:    "http://localhost:8080",
			wantErr: false,
		},
		{
			name:    "bare hostname",
			addr:    "localhost",
			want:    "http://localhost",
			wantErr: false,
		},
		{
			name:    "IP address with port",
			addr:    "192.168.1.1:3000",
			want:    "http://192.168.1.1:3000",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildFabricChatURL(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildFabricChatURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("buildFabricChatURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
