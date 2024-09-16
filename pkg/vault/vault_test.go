package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

type mockCertAuth struct {
	CertAuth
	mockConfigureTLS func(*vault.Config) error
}

// ConfigureTLS overrides the original method with our mock
func (m *mockCertAuth) ConfigureTLS(config *vault.Config) error {
	return m.mockConfigureTLS(config)
}

func TestNewVaultClient(t *testing.T) {
	tests := []struct {
		name       string
		authMethod AuthMethod
		setupMock  func(*httptest.Server)
		wantErr    bool
	}{
		{
			name:       "TokenAuth_Success",
			authMethod: TokenAuth{Token: "test-token"},
			setupMock: func(s *httptest.Server) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "test-token", r.Header.Get("X-Vault-Token"))
					if r.URL.Path == "/v1/auth/token/lookup-self" {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"data": {"id": "test-token"}}`))
					} else {
						w.WriteHeader(http.StatusOK)
					}
				})
			},
			wantErr: false,
		},
		{
			name: "AppRoleAuth_Success",
			authMethod: AppRoleAuth{
				RoleID:   "test-role-id",
				SecretID: "test-secret-id",
			},
			setupMock: func(s *httptest.Server) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "/v1/auth/approle/login", r.URL.Path)
					assert.Equal(t, http.MethodPut, r.Method)
					var payload map[string]interface{}
					json.NewDecoder(r.Body).Decode(&payload)
					assert.Equal(t, "test-role-id", payload["role_id"])
					assert.Equal(t, "test-secret-id", payload["secret_id"])
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"auth": {"client_token": "test-client-token"}}`))
				})
			},
			wantErr: false,
		},
		{
			name: "CertAuth_Success",
			authMethod: CertAuth{
				CertFile: "test-cert.pem",
				KeyFile:  "test-key.pem",
			},
			setupMock: func(s *httptest.Server) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "/v1/auth/cert/login", r.URL.Path)
					assert.Equal(t, http.MethodPut, r.Method)
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"auth": {"client_token": "test-client-token"}}`))
				})
			},
			wantErr: false,
		},
		{
			name: "JWTAuth_Success",
			authMethod: JWTAuth{
				Role: "test-role",
				JWT:  "test-jwt",
			},
			setupMock: func(s *httptest.Server) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "/v1/auth/jwt/login", r.URL.Path)
					assert.Equal(t, http.MethodPut, r.Method)
					var payload map[string]interface{}
					json.NewDecoder(r.Body).Decode(&payload)
					assert.Equal(t, "test-role", payload["role"])
					assert.Equal(t, "test-jwt", payload["jwt"])
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"auth": {"client_token": "test-client-token"}}`))
				})
			},
			wantErr: false,
		},
		{
			name: "K8sAuth_Success",
			authMethod: K8sAuth{
				Role: "test-role",
				JWT:  "test-jwt",
			},
			setupMock: func(s *httptest.Server) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "/v1/auth/kubernetes/login", r.URL.Path)
					assert.Equal(t, http.MethodPut, r.Method)
					var payload map[string]interface{}
					json.NewDecoder(r.Body).Decode(&payload)
					assert.Equal(t, "test-role", payload["role"])
					assert.Equal(t, "test-jwt", payload["jwt"])
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"auth": {"client_token": "test-client-token"}}`))
				})
			},
			wantErr: false,
		},
		{
			name:       "TokenAuth_Failure",
			authMethod: TokenAuth{Token: "invalid-token"},
			setupMock: func(s *httptest.Server) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/auth/token/lookup-self" {
						w.WriteHeader(http.StatusForbidden)
						w.Write([]byte(`{"errors": ["invalid token"]}`))
					} else {
						w.WriteHeader(http.StatusForbidden)
					}
				})
			},
			wantErr: true,
		},
		{
			name: "AppRoleAuth_Failure",
			authMethod: AppRoleAuth{
				RoleID:   "invalid-role-id",
				SecretID: "invalid-secret-id",
			},
			setupMock: func(s *httptest.Server) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"errors": ["invalid AppRole credentials"]}`))
				})
			},
			wantErr: true,
		},
		{
			name: "CertAuth_Failure",
			authMethod: CertAuth{
				CertFile: "invalid-cert.pem",
				KeyFile:  "invalid-key.pem",
			},
			setupMock: func(s *httptest.Server) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"errors": ["invalid certificate"]}`))
				})
			},
			wantErr: true,
		},
		{
			name: "JWTAuth_Failure",
			authMethod: JWTAuth{
				Role: "invalid-role",
				JWT:  "invalid-jwt",
			},
			setupMock: func(s *httptest.Server) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"errors": ["invalid JWT"]}`))
				})
			},
			wantErr: true,
		},
		{
			name: "K8sAuth_Failure",
			authMethod: K8sAuth{
				Role: "invalid-role",
				JWT:  "invalid-jwt",
			},
			setupMock: func(s *httptest.Server) {
				s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"errors": ["invalid Kubernetes credentials"]}`))
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// This default handler should never be called
				t.Errorf("Unexpected request to %s", r.URL.Path)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()

			// Apply the test-specific mock
			tt.setupMock(server)

			// Create a copy of the auth method to avoid modifying the original
			authMethod := tt.authMethod

			// Mock the TLS configuration for CertAuth
			if certAuth, ok := authMethod.(CertAuth); ok {
				authMethod = &mockCertAuth{
					CertAuth: certAuth,
					mockConfigureTLS: func(config *vault.Config) error {
						// Do nothing for the test
						return nil
					},
				}
			}

			client, err := NewVaultClient(server.URL, authMethod)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestVaultClient_Operations(t *testing.T) {
	tests := []struct {
		name        string
		operation   string
		path        string
		input       map[string]interface{}
		setupMock   func(w http.ResponseWriter, r *http.Request)
		expectedErr bool
		checkResult func(t *testing.T, result interface{})
	}{
		{
			name:      "ReadSecret_Success",
			operation: "Read",
			path:      "secret/data/test",
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data": {"data": {"foo": "bar"}}}`))
			},
			expectedErr: false,
			checkResult: func(t *testing.T, result interface{}) {
				data, ok := result.(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, "bar", data["data"].(map[string]interface{})["foo"])
			},
		},
		{
			name:      "ReadSecret_NotFound",
			operation: "Read",
			path:      "secret/data/nonexistent",
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/secret/data/nonexistent", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				w.WriteHeader(http.StatusNotFound)
			},
			expectedErr: true,
		},
		{
			name:      "WriteSecret_Success",
			operation: "Write",
			path:      "secret/data/test",
			input:     map[string]interface{}{"foo": "bar"},
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)
				var payload map[string]interface{}
				json.NewDecoder(r.Body).Decode(&payload)
				assert.Equal(t, map[string]interface{}{"foo": "bar"}, payload)
				w.WriteHeader(http.StatusNoContent)
			},
			expectedErr: false,
		},
		{
			name:      "WriteSecret_Failure",
			operation: "Write",
			path:      "secret/data/test",
			input:     map[string]interface{}{"foo": "bar"},
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"errors": ["permission denied"]}`))
			},
			expectedErr: true,
		},
		{
			name:      "DeleteSecret_Success",
			operation: "Delete",
			path:      "secret/data/test",
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodDelete, r.Method)
				w.WriteHeader(http.StatusNoContent)
			},
			expectedErr: false,
		},
		{
			name:      "DeleteSecret_Failure",
			operation: "Delete",
			path:      "secret/data/test",
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/secret/data/test", r.URL.Path)
				assert.Equal(t, http.MethodDelete, r.Method)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"errors": ["permission denied"]}`))
			},
			expectedErr: true,
		},
		{
			name:      "EnableAuditDevice_Success",
			operation: "EnableAudit",
			path:      "test-audit",
			input: map[string]interface{}{
				"type":        "file",
				"description": "Test audit device",
				"options":     map[string]string{"file_path": "/tmp/audit.log"},
			},
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/sys/audit":
					assert.Equal(t, http.MethodGet, r.Method)
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"data":{}}`)) // Return a valid, but empty, JSON object
				case "/v1/sys/audit/test-audit":
					assert.Equal(t, http.MethodPut, r.Method)
					var payload map[string]interface{}
					json.NewDecoder(r.Body).Decode(&payload)
					assert.Equal(t, "file", payload["type"])
					assert.Equal(t, "Test audit device", payload["description"])
					assert.Equal(t, map[string]interface{}{"file_path": "/tmp/audit.log"}, payload["options"])
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Fatalf("Unexpected request to %s", r.URL.Path)
				}
			},
			expectedErr: false,
		},
		{
			name:      "EnableAuditDevice_Failure",
			operation: "EnableAudit",
			path:      "test-audit",
			input: map[string]interface{}{
				"type":        "file",
				"description": "Test audit device",
				"options":     map[string]string{"file_path": "/tmp/audit.log"},
			},
			setupMock: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/sys/audit":
					assert.Equal(t, http.MethodGet, r.Method)
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"test-audit/": {"type": "file"}}`))
				case "/v1/sys/audit/test-audit":
					t.Fatalf("Unexpected request to enable existing audit device")
				default:
					t.Fatalf("Unexpected request to %s", r.URL.Path)
				}
			},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.setupMock))
			defer server.Close()

			client, _ := vault.NewClient(&vault.Config{Address: server.URL})
			vaultClient := &VaultClient{client}

			var err error
			var result interface{}

			switch tt.operation {
			case "Read":
				result, err = vaultClient.ReadSecret(tt.path)
			case "Write":
				err = vaultClient.WriteSecret(tt.path, tt.input)
			case "Delete":
				err = vaultClient.DeleteSecret(tt.path)
			case "EnableAudit":
				err = vaultClient.EnableAuditDevice(tt.path, tt.input["type"].(string), tt.input["description"].(string), tt.input["options"].(map[string]string))
			}

			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, result)
				}
			}
		})
	}
}
