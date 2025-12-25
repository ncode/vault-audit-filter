/*
Copyright © 2024 Juliano Martinez <juliano@martinez.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestSetupCmd_MissingToken(t *testing.T) {
	viper.Reset()
	viper.Set("vault.token", "")

	err := setupCmd.RunE(setupCmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vault.token is required")
}

func TestSetupCmd_VaultClientError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors": ["permission denied"]}`))
	}))
	defer server.Close()

	viper.Reset()
	viper.Set("vault.token", "test-token")
	viper.Set("vault.address", server.URL)

	err := setupCmd.RunE(setupCmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to setup vault client")
}

func TestSetupCmd_EnableAuditError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": {"id": "test-token"}}`))
		case "/v1/sys/audit":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"test-audit/": {"type": "socket"}}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	viper.Reset()
	viper.Set("vault.token", "test-token")
	viper.Set("vault.address", server.URL)
	viper.Set("vault.audit_path", "test-audit")
	viper.Set("vault.audit_address", "127.0.0.1:1269")
	viper.Set("vault.audit_description", "Test audit")

	err := setupCmd.RunE(setupCmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to enable audit device")
}

func TestSetupCmd_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": {"id": "test-token"}}`))
		case "/v1/sys/audit":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": {}}`))
		case "/v1/sys/audit/test-audit":
			assert.Equal(t, http.MethodPut, r.Method)
			var payload map[string]interface{}
			json.NewDecoder(r.Body).Decode(&payload)
			assert.Equal(t, "socket", payload["type"])
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("Unexpected request to %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	viper.Reset()
	viper.Set("vault.token", "test-token")
	viper.Set("vault.address", server.URL)
	viper.Set("vault.audit_path", "test-audit")
	viper.Set("vault.audit_address", "127.0.0.1:1269")
	viper.Set("vault.audit_description", "Test audit")

	err := setupCmd.RunE(setupCmd, []string{})
	assert.NoError(t, err)
}
