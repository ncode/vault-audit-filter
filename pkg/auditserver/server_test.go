package auditserver

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/expr-lang/expr"
	"github.com/spf13/viper"
	"log/slog"
)

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
		},
		{
			Name: "critical_events",
			Rules: []string{
				`Request.Operation == "delete" && Auth.PolicyResults.Allowed == true`,
				`Request.Path startsWith "secret/metadata/" && Auth.PolicyResults.Allowed == true`,
			},
			LogFile: LogFileConfig{
				FilePath:   tempDir + "/critical_events.log",
				MaxSize:    1,
				MaxBackups: 1,
				MaxAge:     1,
				Compress:   false,
			},
		},
	}

	// Initialize viper with the rule group configurations
	viper.Set("rule_groups", ruleGroupConfigs)

	// Create the AuditServer
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	as := New(logger)

	tests := []struct {
		name         string
		input        AuditLog
		expectedLogs map[string]bool // Map of log file names to whether they should contain the log
	}{
		{
			name: "Normal operation - update",
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
				tempDir + "/critical_events.log":   false,
			},
		},
		// Add more test cases as needed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize the audit log to JSON
			frame, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("Failed to marshal audit log: %v", err)
			}

			// Call React
			as.React(frame, &mockConn{})

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

			// Clean up log files for next test
			for logFile := range tt.expectedLogs {
				os.Remove(logFile)
			}
		})
	}
}

func TestNew(t *testing.T) {
	// Define rule group configurations
	ruleGroupConfigs := []RuleGroupConfig{
		{
			Name: "test_group",
			Rules: []string{
				`Request.Operation == "update"`,
			},
			LogFile: LogFileConfig{
				FilePath:   "test.log",
				MaxSize:    1,
				MaxBackups: 1,
				MaxAge:     1,
				Compress:   false,
			},
		},
	}

	// Initialize viper with the rule group configurations
	viper.Set("rule_groups", ruleGroupConfigs)

	// Test with nil logger
	server := New(nil)
	if server.logger == nil {
		t.Errorf("Expected non-nil logger when initialized with nil")
	}

	if len(server.ruleGroups) != len(ruleGroupConfigs) {
		t.Errorf("Expected %d rule groups, got %d", len(ruleGroupConfigs), len(server.ruleGroups))
	}

	// Test with custom logger
	customLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server = New(customLogger)
	if server.logger != customLogger {
		t.Errorf("Expected custom logger to be used")
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

	// Modify audit log to not match
	auditLog.Request.Operation = "read"

	if rg.shouldLog(auditLog) {
		t.Errorf("Expected shouldLog to return false, got true")
	}
}
