package auditserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/expr-lang/expr"
	"github.com/panjf2000/gnet"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockForwarder struct {
	mock.Mock
	forwardedData []byte
	mu            sync.Mutex
}

func (m *MockForwarder) Forward(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forwardedData = append(m.forwardedData, data...)
	args := m.Called(data)
	return args.Error(0)
}

func (m *MockForwarder) GetForwardedData() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.forwardedData
}

// MockMessenger is a mock implementation of the Messenger interface
type MockMessenger struct {
	SendFunc func(message string) error
}

func (m *MockMessenger) Send(message string) error {
	if m.SendFunc != nil {
		return m.SendFunc(message)
	}
	return nil
}

// mockConn is a mock implementation of gnet.Conn
type mockConn struct{}

func (m *mockConn) Read() []byte                        { return nil }
func (m *mockConn) ReadN(n int) (int, []byte)           { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Close() error                        { return nil }
func (m *mockConn) LocalAddr() net.Addr                 { return nil }
func (m *mockConn) RemoteAddr() net.Addr                { return nil }
func (m *mockConn) Context() interface{}                { return nil }
func (m *mockConn) SetContext(ctx interface{})          {}
func (m *mockConn) Wake() error                         { return nil }
func (m *mockConn) ResetBuffer()                        {}
func (m *mockConn) ReadBytes() []byte                   { return nil }
func (m *mockConn) ShiftN(n int) (size int)             { return 0 }
func (m *mockConn) InboundBuffer() *bytes.Buffer        { return nil }
func (m *mockConn) OutboundBuffer() *bytes.Buffer       { return nil }
func (m *mockConn) AsyncWrite(buf []byte) (err error)   { return nil }
func (m *mockConn) AsyncWritev(bs [][]byte) (err error) { return nil }
func (m *mockConn) SendTo(buf []byte) (err error)       { return nil }
func (m *mockConn) WriteFrame(buf []byte) (err error)   { return nil }
func (m *mockConn) BufferLength() int                   { return 0 }
func (m *mockConn) Peek(n int) (buf []byte, err error)  { return nil, nil }
func (m *mockConn) Next(n int) (buf []byte, err error)  { return nil, nil }

func TestAuditServer_React(t *testing.T) {
	// Create a temporary directory for log files
	tempDir := t.TempDir()

	// Define rule group configurations
	ruleGroupConfigs := []RuleGroupConfig{
		{
			Name: "normal_operations",
			Rules: []string{
				`Request.Operation in ["read", "update"] && Request.Path startsWith "secret/data/" && Auth.PolicyResults.Allowed == true`,
			},
			LogFile: LogFileConfig{
				FilePath:   tempDir + "/normal_operations.log",
				MaxSize:    1,
				MaxBackups: 1,
				MaxAge:     1,
				Compress:   false,
			},
			Messaging: Messaging{
				Type:       "mattermost_webhook",
				WebhookURL: "http://example.com/webhook",
			},
		},
	}

	// Initialize viper with the rule group configurations
	viper.Set("rule_groups", ruleGroupConfigs)

	for _, tt := range []struct {
		name                string
		input               AuditLog
		inputFrame          []byte
		expectedLogs        map[string]bool // Map of log file names to whether they should contain the log
		expectAction        gnet.Action     // Expected gnet.Action
		messengerError      error           // Error to be returned by Messenger.Send
		expectedLogMessages []string        // Expected log messages to be present in the logs
	}{
		{
			name:       "Invalid JSON input",
			inputFrame: []byte("Invalid JSON"),
			expectedLogs: map[string]bool{
				tempDir + "/normal_operations.log": false,
			},
			expectAction: gnet.Close,
			expectedLogMessages: []string{
				"Error parsing audit log",
			},
		},
		{
			name: "Messenger.Send failure",
			input: AuditLog{
				Type: "request",
				Time: "2024-09-17T13:00:00Z",
				Auth: Auth{
					DisplayName: "user1",
					Policies:    []string{"default", "writer"},
					PolicyResults: struct {
						Allowed          bool `json:"allowed"`
						GrantingPolicies []struct {
							Name        string `json:"name"`
							NamespaceID string `json:"namespace_id"`
							Type        string `json:"type"`
						} `json:"granting_policies"`
					}{
						Allowed: true,
					},
				},
				Request: Request{
					Operation: "update",
					Path:      "secret/data/myapp/config",
				},
			},
			expectedLogs: map[string]bool{
				tempDir + "/normal_operations.log": true,
			},
			expectAction:   gnet.Close,
			messengerError: fmt.Errorf("failed to send message"),
			expectedLogMessages: []string{
				"Failed to send notification",
			},
		},
		{
			name: "No matching rule",
			input: AuditLog{
				Type: "request",
				Time: "2024-09-17T13:00:00Z",
				Auth: Auth{
					DisplayName: "user2",
					Policies:    []string{"default"},
					PolicyResults: struct {
						Allowed          bool `json:"allowed"`
						GrantingPolicies []struct {
							Name        string `json:"name"`
							NamespaceID string `json:"namespace_id"`
							Type        string `json:"type"`
						} `json:"granting_policies"`
					}{
						Allowed: false,
					},
				},
				Request: Request{
					Operation: "read",
					Path:      "secret/data/myapp/config",
				},
			},
			expectedLogs: map[string]bool{
				tempDir + "/normal_operations.log": false,
			},
			expectAction: gnet.Close,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var frame []byte
			if tt.inputFrame != nil {
				frame = tt.inputFrame
			} else {
				// Serialize the audit log to JSON
				var err error
				frame, err = json.Marshal(tt.input)
				if err != nil {
					t.Fatalf("Failed to marshal audit log: %v", err)
				}
			}

			// Capture logs
			var logBuffer bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

			// Create the AuditServer
			as := New(logger)

			// Set up mock messenger if needed
			for i := range as.ruleGroups {
				rg := &as.ruleGroups[i]
				if rg.Messenger != nil {
					// Replace Messenger with MockMessenger
					rg.Messenger = &MockMessenger{
						SendFunc: func(message string) error {
							return tt.messengerError
						},
					}
				}
			}

			// Call React
			_, action := as.React(frame, &mockConn{})

			if action != tt.expectAction {
				t.Errorf("Expected action %v, got %v", tt.expectAction, action)
			}

			// Give some time for the log to be written
			time.Sleep(100 * time.Millisecond)

			// Check log files
			for logFile, shouldContain := range tt.expectedLogs {
				content, err := ioutil.ReadFile(logFile)
				if err != nil {
					if os.IsNotExist(err) && !shouldContain {
						// File doesn't exist as expected
						continue
					}
					t.Fatalf("Failed to read log file '%s': %v", logFile, err)
				}

				if shouldContain {
					if !bytes.Contains(content, frame) {
						t.Errorf("Expected log file '%s' to contain the audit log", logFile)
					}
				} else {
					if len(content) > 0 {
						t.Errorf("Expected log file '%s' to be empty", logFile)
					}
				}
			}

			// Check logs
			logOutput := logBuffer.String()
			for _, msg := range tt.expectedLogMessages {
				if !bytes.Contains([]byte(logOutput), []byte(msg)) {
					t.Errorf("Expected log output to contain '%s', got %s", msg, logOutput)
				}
			}

			// Clean up log files for next test
			for logFile := range tt.expectedLogs {
				os.Remove(logFile)
			}
		})
	}
}

func TestNew(t *testing.T) {
	// Define rule group configurations with an invalid rule and messenger type
	ruleGroupConfigs := []RuleGroupConfig{
		{
			Name: "test_group",
			Rules: []string{
				`Request.Operation == "update"`,
				`Invalid rule syntax`,
			},
			LogFile: LogFileConfig{
				FilePath:   "test.log",
				MaxSize:    1,
				MaxBackups: 1,
				MaxAge:     1,
				Compress:   false,
			},
			Messaging: Messaging{
				Type: "invalid_messenger",
			},
		},
	}

	// Initialize viper with the rule group configurations
	viper.Set("rule_groups", ruleGroupConfigs)

	// Capture logs
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	server := New(logger)
	if len(server.ruleGroups) != len(ruleGroupConfigs) {
		t.Errorf("Expected %d rule groups, got %d", len(ruleGroupConfigs), len(server.ruleGroups))
	}

	rg := server.ruleGroups[0]

	// Check that one rule compiled successfully, and one failed
	if len(rg.CompiledRules) != 1 {
		t.Errorf("Expected 1 compiled rule, got %d", len(rg.CompiledRules))
	}

	// Check that Messenger is nil due to invalid type
	if rg.Messenger != nil {
		t.Errorf("Expected Messenger to be nil for invalid type, got %v", rg.Messenger)
	}

	// Check logs for error messages
	logOutput := logBuffer.String()
	if !bytes.Contains([]byte(logOutput), []byte("Failed to compile rule")) {
		t.Errorf("Expected log output to contain 'Failed to compile rule', got %s", logOutput)
	}

	if !bytes.Contains([]byte(logOutput), []byte("Invalid messenger type")) {
		t.Errorf("Expected log output to contain 'Invalid messenger type', got %s", logOutput)
	}
}

func TestRuleGroup_shouldLog(t *testing.T) {
	// Define a sample audit log
	auditLog := &AuditLog{
		Type: "request",
		Time: "2024-09-17T13:00:00Z",
		Auth: Auth{
			DisplayName: "user1",
			Policies:    []string{"default", "writer"},
			PolicyResults: struct {
				Allowed          bool `json:"allowed"`
				GrantingPolicies []struct {
					Name        string `json:"name"`
					NamespaceID string `json:"namespace_id"`
					Type        string `json:"type"`
				} `json:"granting_policies"`
			}{
				Allowed: true,
			},
		},
		Request: Request{
			Operation: "update",
			Path:      "secret/data/myapp/config",
		},
	}

	t.Run("Matching rule", func(t *testing.T) {
		// Compile a rule
		ruleStr := `Request.Operation == "update" && Request.Path startsWith "secret/data/" && Auth.PolicyResults.Allowed == true`
		program, err := expr.Compile(ruleStr, expr.Env(&AuditLog{}))
		if err != nil {
			t.Fatalf("Failed to compile rule: %v", err)
		}

		// Create a RuleGroup
		rg := &RuleGroup{
			Name: "test_group",
			CompiledRules: []CompiledRule{
				{Program: program},
			},
		}

		// Test shouldLog
		if !rg.shouldLog(auditLog) {
			t.Errorf("Expected shouldLog to return true, got false")
		}
	})

	t.Run("Non-matching rule", func(t *testing.T) {
		// Compile a rule that does not match
		ruleStr := `Request.Operation == "delete"`
		program, err := expr.Compile(ruleStr, expr.Env(&AuditLog{}))
		if err != nil {
			t.Fatalf("Failed to compile rule: %v", err)
		}

		rg := &RuleGroup{
			Name: "test_group",
			CompiledRules: []CompiledRule{
				{Program: program},
			},
		}

		if rg.shouldLog(auditLog) {
			t.Errorf("Expected shouldLog to return false, got true")
		}
	})

	t.Run("No compiled rules", func(t *testing.T) {
		rg := &RuleGroup{
			Name:          "test_group",
			CompiledRules: nil,
		}

		if !rg.shouldLog(auditLog) {
			t.Errorf("Expected shouldLog to return true when no compiled rules, got false")
		}
	})

	t.Run("expr.Run returns error", func(t *testing.T) {
		// Expression that will cause a runtime error (division by zero)
		ruleStr := `1 / 0 == 0`

		program, err := expr.Compile(ruleStr)
		if err != nil {
			t.Fatalf("Failed to compile rule: %v", err)
		}

		rg := &RuleGroup{
			Name: "test_group",
			CompiledRules: []CompiledRule{
				{Program: program},
			},
		}

		if rg.shouldLog(auditLog) {
			t.Errorf("Expected shouldLog to return false when expr.Run returns error, got true")
		}
	})
}

func TestAuditServer_React_WithForwarding(t *testing.T) {
	// Create a temporary directory for log files
	tempDir := t.TempDir()

	// Create a mock HTTP server for webhook
	mockWebhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockWebhook.Close()

	// Define rule group configurations with forwarding
	ruleGroupConfigs := []RuleGroupConfig{
		{
			Name: "normal_operations",
			Rules: []string{
				`Request.Operation in ["read", "update"] && Request.Path startsWith "secret/data/" && Auth.PolicyResults.Allowed == true`,
			},
			LogFile: LogFileConfig{
				FilePath:   tempDir + "/normal_operations.log",
				MaxSize:    1,
				MaxBackups: 1,
				MaxAge:     1,
				Compress:   false,
			},
			Messaging: Messaging{
				Type:       "mattermost_webhook",
				WebhookURL: mockWebhook.URL,
			},
			Forwarding: ForwardingConfig{
				Enabled: true,
				Address: "127.0.0.1:9001",
			},
		},
		{
			Name: "critical_events",
			Rules: []string{
				`Request.Operation == "delete" && Auth.PolicyResults.Allowed == true`,
			},
			LogFile: LogFileConfig{
				FilePath:   tempDir + "/critical_events.log",
				MaxSize:    1,
				MaxBackups: 1,
				MaxAge:     1,
				Compress:   false,
			},
			Forwarding: ForwardingConfig{
				Enabled: true,
				Address: "127.0.0.1:9002",
			},
		},
	}

	// Initialize viper with the rule group configurations
	viper.Set("rule_groups", ruleGroupConfigs)

	testCases := []struct {
		name              string
		input             AuditLog
		expectedLogs      map[string]bool
		expectAction      gnet.Action
		expectedForwarded bool
		expectedForwarder int // 0 for mockForwarder1, 1 for mockForwarder2
	}{
		{
			name: "Normal operation - should forward",
			input: AuditLog{
				Type: "request",
				Auth: Auth{
					PolicyResults: struct {
						Allowed          bool `json:"allowed"`
						GrantingPolicies []struct {
							Name        string `json:"name"`
							NamespaceID string `json:"namespace_id"`
							Type        string `json:"type"`
						} `json:"granting_policies"`
					}{
						Allowed: true,
					},
				},
				Request: Request{
					Operation: "update",
					Path:      "secret/data/myapp/config",
				},
			},
			expectedLogs: map[string]bool{
				tempDir + "/normal_operations.log": true,
				tempDir + "/critical_events.log":   false,
			},
			expectAction:      gnet.Close,
			expectedForwarded: true,
			expectedForwarder: 0,
		},
		{
			name: "Critical event - should forward",
			input: AuditLog{
				Type: "request",
				Auth: Auth{
					PolicyResults: struct {
						Allowed          bool `json:"allowed"`
						GrantingPolicies []struct {
							Name        string `json:"name"`
							NamespaceID string `json:"namespace_id"`
							Type        string `json:"type"`
						} `json:"granting_policies"`
					}{
						Allowed: true,
					},
				},
				Request: Request{
					Operation: "delete",
					Path:      "secret/data/myapp/config",
				},
			},
			expectedLogs: map[string]bool{
				tempDir + "/normal_operations.log": false,
				tempDir + "/critical_events.log":   true,
			},
			expectAction:      gnet.Close,
			expectedForwarded: true,
			expectedForwarder: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock forwarders
			mockForwarder1 := &MockForwarder{}
			mockForwarder2 := &MockForwarder{}

			// Serialize the audit log to JSON
			frame, err := json.Marshal(tc.input)
			assert.NoError(t, err)

			// Create the AuditServer
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
			as := New(logger)

			// Replace the forwarders with our mocks
			as.ruleGroups[0].Forwarder = mockForwarder1
			as.ruleGroups[1].Forwarder = mockForwarder2

			// Set expectations on the mock forwarders
			mockForwarder1.On("Forward", frame).Return(nil).Maybe()
			mockForwarder2.On("Forward", frame).Return(nil).Maybe()

			// Call React
			_, action := as.React(frame, &mockConn{})

			assert.Equal(t, tc.expectAction, action)

			// Give some time for logging and forwarding
			time.Sleep(100 * time.Millisecond)

			// Check log files
			for logFile, shouldContain := range tc.expectedLogs {
				content, err := ioutil.ReadFile(logFile)
				if shouldContain {
					assert.NoError(t, err)
					assert.Contains(t, string(content), string(frame))
				} else {
					if !os.IsNotExist(err) {
						assert.Empty(t, string(content))
					}
				}
			}

			// Check forwarding
			if tc.expectedForwarded {
				var expectedForwarder *MockForwarder
				var unexpectedForwarder *MockForwarder
				if tc.expectedForwarder == 0 {
					expectedForwarder = mockForwarder1
					unexpectedForwarder = mockForwarder2
				} else {
					expectedForwarder = mockForwarder2
					unexpectedForwarder = mockForwarder1
				}
				assert.NotEmpty(t, expectedForwarder.GetForwardedData())
				assert.Equal(t, string(frame), string(expectedForwarder.GetForwardedData()))
				assert.Empty(t, unexpectedForwarder.GetForwardedData())
			} else {
				assert.Empty(t, mockForwarder1.GetForwardedData())
				assert.Empty(t, mockForwarder2.GetForwardedData())
			}

			// Verify that the mock expectations were met
			mockForwarder1.AssertExpectations(t)
			mockForwarder2.AssertExpectations(t)

			// Clean up log files for next test
			for logFile := range tc.expectedLogs {
				os.Remove(logFile)
			}
		})
	}
}
