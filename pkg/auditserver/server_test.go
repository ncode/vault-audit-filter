package auditserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/expr-lang/expr/vm"
	"github.com/stretchr/testify/require"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/expr-lang/expr"
	"github.com/panjf2000/gnet/v2"
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

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

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
				Type:       "slack_webhook",
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
			expectAction:   gnet.None,
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
			logBuffer := &lockedBuffer{}
			logger := slog.New(slog.NewJSONHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

			// Create the AuditServer
			as, _ := New(logger)

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
			_, action := as.React(frame, nil)

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
	logBuffer := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	server, _ := New(logger)
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

func TestNew_DefaultRuleGroup_WhenMissingOrEmpty(t *testing.T) {
	viper.Reset()

	// Missing rule_groups
	server, err := New(nil)
	require.NoError(t, err)
	require.NotNil(t, server)
	require.Len(t, server.ruleGroups, 1)
	assert.Len(t, server.ruleGroups[0].CompiledRules, 0)
	assert.NotNil(t, server.ruleGroups[0].Logger)

	// Empty rule_groups
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{})
	server, err = New(nil)
	require.NoError(t, err)
	require.Len(t, server.ruleGroups, 1)
}

func TestNew_AsyncDefaults(t *testing.T) {
	viper.Reset()
	server, err := New(nil)
	require.NoError(t, err)
	require.NotNil(t, server)
	assert.Equal(t, "drop", server.asyncEnqueueMode)
	assert.Equal(t, 5*time.Millisecond, server.asyncEnqueueTimeout)
	assert.Equal(t, 2, server.asyncWorkers)
	assert.Equal(t, 20, server.asyncQueueSize)
	assert.Equal(t, 5*time.Second, server.asyncTimeout)
}

func TestNew_InvalidEnqueueModeFallsBackToDrop(t *testing.T) {
	viper.Reset()
	viper.Set("async.enqueue_mode", "invalid")
	viper.Set("async.enqueue_timeout", "12ms")

	server, err := New(nil)
	require.NoError(t, err)
	assert.Equal(t, "drop", server.asyncEnqueueMode)
	assert.Equal(t, 12*time.Millisecond, server.asyncEnqueueTimeout)
}

func TestSideQueue_DropsWhenFull(t *testing.T) {
	viper.Reset()
	viper.Set("async.queue_size", 1)
	oldWorkers := defaultSideWorkers
	defaultSideWorkers = 0
	defer func() { defaultSideWorkers = oldWorkers }()

	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name":     "rg",
			"rules":    []string{"true"},
			"log_file": map[string]interface{}{"file_path": "/tmp/test.log", "max_size": 1},
			"messaging": map[string]interface{}{
				"type":        "slack_webhook",
				"webhook_url": "http://example.com",
			},
		},
	})

	srv, err := New(nil)
	require.NoError(t, err)

	frame := []byte(`{"type":"request","time":"2000-01-01T00:00:00Z","auth":{},"request":{},"response":{}}`)
	_, _ = srv.React(frame, nil)
	_, _ = srv.React(frame, nil)

	assert.Equal(t, uint64(1), srv.sideDrops.Load())
}

func TestReact_AsyncMessengerCalled(t *testing.T) {
	viper.Reset()
	viper.Set("async.queue_size", 10)
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name":     "rg",
			"rules":    []string{"true"},
			"log_file": map[string]interface{}{"file_path": "/tmp/test.log", "max_size": 1},
			"messaging": map[string]interface{}{
				"type":        "slack_webhook",
				"webhook_url": "http://example.com",
			},
		},
	})

	srv, err := New(nil)
	require.NoError(t, err)

	called := make(chan struct{}, 1)
	for i := range srv.ruleGroups {
		srv.ruleGroups[i].Messenger = &MockMessenger{SendFunc: func(string) error {
			called <- struct{}{}
			return nil
		}}
	}

	frame := []byte(`{"type":"request","time":"2000-01-01T00:00:00Z","auth":{},"request":{},"response":{}}`)
	_, action := srv.React(frame, nil)
	assert.Equal(t, gnet.None, action)

	select {
	case <-called:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("messenger not called")
	}
}

func TestNew_AsyncWorkersCanBeDisabled(t *testing.T) {
	viper.Reset()
	viper.Set("async.queue_size", 10)
	viper.Set("async.workers", 0)
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name":     "rg",
			"rules":    []string{"true"},
			"log_file": map[string]interface{}{"file_path": "/tmp/test.log", "max_size": 1},
			"messaging": map[string]interface{}{
				"type":        "slack_webhook",
				"webhook_url": "http://example.com",
			},
		},
	})

	srv, err := New(nil)
	require.NoError(t, err)

	called := make(chan struct{}, 1)
	for i := range srv.ruleGroups {
		srv.ruleGroups[i].Messenger = &MockMessenger{SendFunc: func(string) error {
			called <- struct{}{}
			return nil
		}}
	}

	frame := []byte(`{"type":"request","time":"2000-01-01T00:00:00Z","auth":{},"request":{},"response":{}}`)
	_, action := srv.React(frame, nil)
	assert.Equal(t, gnet.None, action)

	select {
	case <-called:
		t.Fatalf("messenger should not be called when async.workers=0")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestNew_AsyncWorkersCanOverrideDefault(t *testing.T) {
	viper.Reset()
	viper.Set("async.queue_size", 10)
	viper.Set("async.workers", 1)
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name":     "rg",
			"rules":    []string{"true"},
			"log_file": map[string]interface{}{"file_path": "/tmp/test.log", "max_size": 1},
			"messaging": map[string]interface{}{
				"type":        "slack_webhook",
				"webhook_url": "http://example.com",
			},
		},
	})

	oldWorkers := defaultSideWorkers
	defaultSideWorkers = 0
	defer func() { defaultSideWorkers = oldWorkers }()

	srv, err := New(nil)
	require.NoError(t, err)

	called := make(chan struct{}, 1)
	for i := range srv.ruleGroups {
		srv.ruleGroups[i].Messenger = &MockMessenger{SendFunc: func(string) error {
			called <- struct{}{}
			return nil
		}}
	}

	frame := []byte(`{"type":"request","time":"2000-01-01T00:00:00Z","auth":{},"request":{},"response":{}}`)
	_, action := srv.React(frame, nil)
	assert.Equal(t, gnet.None, action)

	select {
	case <-called:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("messenger should be called when async.workers=1")
	}
}

func TestEnqueueSide_DropMode_DropsImmediatelyWhenFull(t *testing.T) {
	as := &AuditServer{
		sideQueue: make(chan sideTask, 1),
	}
	as.sideQueue <- sideTask{}

	start := time.Now()
	ok := as.enqueueSide(sideTask{})
	elapsed := time.Since(start)

	assert.False(t, ok)
	assert.Equal(t, uint64(1), as.sideDrops.Load())
	assert.Less(t, elapsed, 10*time.Millisecond)
}

func TestEnqueueSide_WaitMode_TimesOutWhenFull(t *testing.T) {
	as := &AuditServer{
		sideQueue:           make(chan sideTask, 1),
		asyncEnqueueMode:    "wait",
		asyncEnqueueTimeout: 30 * time.Millisecond,
	}
	as.sideQueue <- sideTask{}

	start := time.Now()
	ok := as.enqueueSide(sideTask{})
	elapsed := time.Since(start)

	assert.False(t, ok)
	assert.Equal(t, uint64(1), as.sideDrops.Load())
	assert.GreaterOrEqual(t, elapsed, 25*time.Millisecond)
}

func TestEnqueueSide_WaitMode_EnqueuesWhenCapacityFrees(t *testing.T) {
	as := &AuditServer{
		sideQueue:           make(chan sideTask, 1),
		asyncEnqueueMode:    "wait",
		asyncEnqueueTimeout: 200 * time.Millisecond,
	}
	as.sideQueue <- sideTask{}

	go func() {
		time.Sleep(25 * time.Millisecond)
		<-as.sideQueue
	}()

	start := time.Now()
	ok := as.enqueueSide(sideTask{})
	elapsed := time.Since(start)

	assert.True(t, ok)
	assert.Equal(t, uint64(0), as.sideDrops.Load())
	assert.GreaterOrEqual(t, elapsed, 20*time.Millisecond)
	assert.Less(t, elapsed, 200*time.Millisecond)
}

func TestEnqueueSide_DurableMode_PersistsWhenQueueFull(t *testing.T) {
	store, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)

	as := &AuditServer{
		logger:              slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})),
		sideQueue:           make(chan sideTask, 1),
		asyncDurableEnabled: true,
		asyncRetryBackoff:   20 * time.Millisecond,
		sideStore:           store,
	}
	as.sideQueue <- sideTask{}

	ok := as.enqueueSide(sideTask{groupName: "g", payload: []byte("x"), payloadStr: "x"})
	require.True(t, ok)
	assert.Equal(t, uint64(0), as.sideDrops.Load())

	tasks, err := as.sideStore.Pending()
	require.NoError(t, err)
	require.Len(t, tasks, 1)
}

func TestProcessSideTask_DurableRetryToDeadLetter(t *testing.T) {
	store, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)

	as := &AuditServer{
		logger:                slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})),
		sideQueue:             make(chan sideTask, 8),
		asyncDurableEnabled:   true,
		asyncRetryMaxAttempts: 2,
		asyncRetryBackoff:     20 * time.Millisecond,
		sideStore:             store,
	}
	as.startSideWorkers(1)

	task := sideTask{
		id:         "task-1",
		groupName:  "g",
		payload:    []byte("x"),
		payloadStr: "x",
		messenger:  &dummyMessenger{sendErr: errors.New("boom")},
	}
	require.NoError(t, as.sideStore.Save(task))

	as.processSideTask(task)

	require.Eventually(t, func() bool {
		pending, err := as.sideStore.Pending()
		if err != nil {
			return false
		}
		if len(pending) != 0 {
			return false
		}
		_, err = os.Stat(filepath.Join(store.deadDir, "task-1.json"))
		return err == nil
	}, 2*time.Second, 25*time.Millisecond)
}

func TestReplayDurablePending_ReplaysStoredTasks(t *testing.T) {
	store, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)

	msg := &dummyMessenger{}
	as := &AuditServer{
		logger:                slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})),
		sideQueue:             make(chan sideTask, 8),
		asyncDurableEnabled:   true,
		asyncRetryMaxAttempts: 2,
		asyncRetryBackoff:     10 * time.Millisecond,
		sideStore:             store,
		ruleGroups: []RuleGroup{{
			Name:      "g",
			Messenger: msg,
		}},
	}
	as.startSideWorkers(1)

	require.NoError(t, as.sideStore.Save(sideTask{id: "task-a", groupName: "g", payload: []byte("a"), payloadStr: "a"}))
	require.NoError(t, as.sideStore.Save(sideTask{id: "task-b", groupName: "g", payload: []byte("b"), payloadStr: "b"}))

	as.replayDurablePending()

	require.Eventually(t, func() bool {
		return msg.Calls() == 2
	}, 2*time.Second, 25*time.Millisecond)

	pending, err := as.sideStore.Pending()
	require.NoError(t, err)
	assert.Len(t, pending, 0)
}

func TestNewWithoutLogger(t *testing.T) {
	// Redirect stdout to capture log output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	server, _ := New(nil)

	assert.NotNil(t, server)
	assert.NotNil(t, server.logger)

	// Test logging
	server.logger.Info("Test log message")

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	out, _ := io.ReadAll(r)
	logEntries := strings.Split(strings.TrimSpace(string(out)), "\n")

	assert.GreaterOrEqual(t, len(logEntries), 1, "Expected at least one log entry")

	var lastLogEntry map[string]interface{}
	err := json.Unmarshal([]byte(logEntries[len(logEntries)-1]), &lastLogEntry)
	assert.NoError(t, err)
	assert.Equal(t, "Test log message", lastLogEntry["msg"])
	assert.Equal(t, "INFO", lastLogEntry["level"])
}

func TestNew_WithRuleGroups(t *testing.T) {
	// Set up a mock configuration
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "test_group",
			"rules": []string{
				"Request.Operation == 'read'",
			},
			"log_file": map[string]interface{}{
				"file_path": "/tmp/test.log",
				"max_size":  10,
			},
			"forwarding": map[string]interface{}{
				"enabled": true,
				"address": "127.0.0.1:9000",
			},
		},
	})

	server, err := New(nil)

	assert.NoError(t, err)
	assert.NotNil(t, server)
	assert.Len(t, server.ruleGroups, 1)
	assert.Equal(t, "test_group", server.ruleGroups[0].Name)
	assert.Len(t, server.ruleGroups[0].CompiledRules, 1)
	assert.NotNil(t, server.ruleGroups[0].Logger)
	assert.NotNil(t, server.ruleGroups[0].Forwarder)
}

func TestNew_WithInvalidRuleGroups(t *testing.T) {
	// Set up an invalid configuration
	viper.Reset()
	viper.Set("rule_groups", "invalid_value")

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	server, err := New(logger)

	assert.Error(t, err)
	assert.Nil(t, server)
	assert.Contains(t, err.Error(), "failed to load rule groups")

	// Verify error was logged
	logOutput := buf.String()
	assert.Contains(t, logOutput, "Failed to load rule groups")
	assert.Contains(t, logOutput, "ERROR")
}

func TestNew_WithValidForwarder(t *testing.T) {
	// Set up a mock configuration with a valid forwarder address
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "test_group",
			"rules": []string{
				"Request.Operation == 'read'",
			},
			"log_file": map[string]interface{}{
				"file_path": "/tmp/test.log",
				"max_size":  10,
			},
			"forwarding": map[string]interface{}{
				"enabled": true,
				"address": "127.0.0.1:9000",
			},
		},
	})

	server, err := New(nil)

	assert.NoError(t, err)
	assert.NotNil(t, server)
	assert.Len(t, server.ruleGroups, 1)
	assert.NotNil(t, server.ruleGroups[0].Forwarder)
}

func TestNew_WithInvalidForwarder(t *testing.T) {
	// Set up a mock configuration with an invalid forwarder address
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "test_group",
			"rules": []string{
				"Request.Operation == 'read'",
			},
			"log_file": map[string]interface{}{
				"file_path": "/tmp/test.log",
				"max_size":  10,
			},
			"forwarding": map[string]interface{}{
				"enabled": true,
				"address": "invalid:address:9000",
			},
		},
	})

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	server, err := New(logger)

	assert.Error(t, err)
	assert.Nil(t, server)
	assert.Contains(t, err.Error(), "failed to create UDP forwarder")

	// Verify error was logged
	logOutput := buf.String()
	assert.Contains(t, logOutput, "Failed to create UDP forwarder")
	assert.Contains(t, logOutput, "ERROR")
}

func TestNew_WithDisabledForwarder(t *testing.T) {
	// Set up a mock configuration with forwarding disabled
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "test_group",
			"rules": []string{
				"Request.Operation == 'read'",
			},
			"log_file": map[string]interface{}{
				"file_path": "/tmp/test.log",
				"max_size":  10,
			},
			"forwarding": map[string]interface{}{
				"enabled": false,
				"address": "127.0.0.1:9000",
			},
		},
	})

	server, err := New(nil)

	assert.NoError(t, err)
	assert.NotNil(t, server)
	assert.Len(t, server.ruleGroups, 1)
	assert.Nil(t, server.ruleGroups[0].Forwarder)
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
				Type:       "slack_webhook",
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
			expectAction:      gnet.None,
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
			expectAction:      gnet.None,
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
			as, _ := New(logger)

			// Replace the forwarders with our mocks
			as.ruleGroups[0].Forwarder = mockForwarder1
			as.ruleGroups[1].Forwarder = mockForwarder2

			// Set expectations on the mock forwarders
			mockForwarder1.On("Forward", frame).Return(nil).Maybe()
			mockForwarder2.On("Forward", frame).Return(nil).Maybe()

			// Call React
			_, action := as.React(frame, nil)

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

type dummyMessenger struct {
	sendErr error
	mu      sync.Mutex
	calls   int
}

func (d *dummyMessenger) Send(_ string) error {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	return d.sendErr
}

func (d *dummyMessenger) Calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

type dummyForwarder struct {
	forwardErr error
	mu         sync.Mutex
	calls      int
}

type errWriter struct{}

func (e errWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

func (d *dummyForwarder) Forward(_ []byte) error {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	return d.forwardErr
}

func (d *dummyForwarder) Calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

type fakeTrafficConn struct {
	gnet.Conn
	frame []byte
	err   error
	ctx   any
}

func (c *fakeTrafficConn) Next(_ int) ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.frame, nil
}

func (c *fakeTrafficConn) Context() any {
	return c.ctx
}

func (c *fakeTrafficConn) SetContext(ctx any) {
	c.ctx = ctx
}

// minimal JSON frame that parses into an AuditLog
func auditFrame() []byte {
	return []byte(`{"type":"request","time":"2000-01-01T00:00:00Z","auth":{},"request":{},"response":{}}`)
}

// returns a compiled rule that always evaluates to false
func falseProgram(t *testing.T) *vm.Program {
	t.Helper()
	p, err := expr.Compile("false")
	require.NoError(t, err)
	return p
}

func TestReact_Branches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	frame := auditFrame()

	newBufLogger := func() (*bytes.Buffer, *log.Logger) {
		buf := new(bytes.Buffer)
		return buf, log.New(buf, "", 0)
	}

	tests := []struct {
		name         string
		group        RuleGroup
		wantAction   gnet.Action
		wantMsgCalls int
		wantFwdCalls int
	}{
		{
			name: "match_no_side_effects_returns_None",
			group: RuleGroup{
				Name: "matchOnly",
				// len==0 => always matches
				CompiledRules: nil,
				Writer:        new(bytes.Buffer),
			},
			wantAction: gnet.None,
		},
		{
			name: "logger_print_branch_returns_None",
			group: func() RuleGroup {
				// Writer nil so else branch executes
				buf, lg := newBufLogger()
				_ = buf // buffer retained if inspection desired
				return RuleGroup{
					Name:          "loggerPrint",
					CompiledRules: nil,
					Logger:        lg,
					Writer:        nil,
				}
			}(),
			wantAction: gnet.None,
		},
		{
			name: "forwarder_ok_triggers_Close",
			group: RuleGroup{
				Name:          "forwardOK",
				CompiledRules: nil,
				Writer:        new(bytes.Buffer),
				Forwarder:     &dummyForwarder{},
			},
			wantAction:   gnet.None,
			wantFwdCalls: 1,
		},
		{
			name: "forwarder_error_triggers_Close",
			group: RuleGroup{
				Name:          "forwardErr",
				CompiledRules: nil,
				Writer:        new(bytes.Buffer),
				Forwarder:     &dummyForwarder{forwardErr: errors.New("boom")},
			},
			wantAction:   gnet.None,
			wantFwdCalls: 1,
		},
		{
			name: "messenger_error_triggers_Close",
			group: RuleGroup{
				Name:          "msgErr",
				CompiledRules: nil,
				Writer:        new(bytes.Buffer),
				Messenger:     &dummyMessenger{sendErr: errors.New("boom")},
			},
			wantAction:   gnet.None,
			wantMsgCalls: 1,
		},
		{
			name: "no_match_triggers_Close",
			group: RuleGroup{
				Name: "noMatch",
				CompiledRules: []CompiledRule{{
					Program: falseProgram(t),
				}},
				Writer: new(bytes.Buffer),
			},
			wantAction: gnet.Close,
		},
	}

	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			srv := &AuditServer{
				logger:     logger,
				ruleGroups: []RuleGroup{tc.group},
				sideQueue:  make(chan sideTask, 2),
			}
			srv.startSideWorkers(1)

			_, act := srv.React(frame, nil)
			require.Equal(t, tc.wantAction, act)

			if dm, ok := tc.group.Messenger.(*dummyMessenger); ok {
				if tc.wantMsgCalls > 0 {
					require.Eventually(t, func() bool { return dm.Calls() == tc.wantMsgCalls }, time.Second, 10*time.Millisecond)
				} else {
					require.Equal(t, tc.wantMsgCalls, dm.Calls())
				}
			}
			if df, ok := tc.group.Forwarder.(*dummyForwarder); ok {
				if tc.wantFwdCalls > 0 {
					require.Eventually(t, func() bool { return df.Calls() == tc.wantFwdCalls }, time.Second, 10*time.Millisecond)
				} else {
					require.Equal(t, tc.wantFwdCalls, df.Calls())
				}
			}
		})
	}
}

func TestReact_WriteErrorAndLoggerPayloadBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	frame := auditFrame()

	t.Run("writer error branch", func(t *testing.T) {
		srv := &AuditServer{
			logger: logger,
			ruleGroups: []RuleGroup{{
				Name:          "werr",
				CompiledRules: nil,
				Writer:        errWriter{},
			}},
			sideQueue: make(chan sideTask, 1),
		}
		_, action := srv.React(frame, nil)
		require.Equal(t, gnet.None, action)
	})

	t.Run("logger payloadStr branch", func(t *testing.T) {
		msg := &dummyMessenger{}
		buf := new(bytes.Buffer)
		srv := &AuditServer{
			logger: logger,
			ruleGroups: []RuleGroup{{
				Name:          "msg",
				CompiledRules: nil,
				Logger:        log.New(buf, "", 0),
				Writer:        nil,
				Messenger:     msg,
			}},
			sideQueue: make(chan sideTask, 1),
		}
		srv.startSideWorkers(1)

		_, action := srv.React(frame, nil)
		require.Equal(t, gnet.None, action)
		require.Eventually(t, func() bool { return msg.Calls() == 1 }, time.Second, 10*time.Millisecond)
		require.Contains(t, buf.String(), string(frame))
	})
}

func TestRuleGroup_shouldLog_RuntimeErrorContinues(t *testing.T) {
	good, err := expr.Compile(`true`, expr.Env(&AuditLog{}))
	require.NoError(t, err)

	rg := &RuleGroup{CompiledRules: []CompiledRule{{Program: nil}, {Program: good}}}
	assert.True(t, rg.shouldLog(&AuditLog{}))
}

func TestAuditServer_HandleTCPStream(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	writer := new(bytes.Buffer)

	as := &AuditServer{
		logger: logger,
		ruleGroups: []RuleGroup{
			{Name: "default", Writer: writer},
		},
	}

	stream := []byte(string(auditFrame()) + "\n" + string(auditFrame()) + "\r\n")
	remaining := as.handleTCPStream(stream, nil)
	require.Empty(t, remaining)

	frameText := string(auditFrame())
	assert.Equal(t, 2, strings.Count(writer.String(), frameText))

	// split frame across reads and validate carryover behavior
	full := string(auditFrame())
	mid := len(full) / 2
	carry := as.handleTCPStream([]byte(full[:mid]), nil)
	require.NotEmpty(t, carry)

	carry = as.handleTCPStream([]byte(full[mid:]+"\n"), carry)
	require.Empty(t, carry)

	assert.Equal(t, 3, strings.Count(writer.String(), frameText))
}

func TestNew_AuditTransportConfiguration(t *testing.T) {
	viper.Reset()
	server, err := New(nil)
	require.NoError(t, err)
	assert.Equal(t, "udp", server.auditTransport)

	viper.Reset()
	viper.Set("vault.audit_protocol", "tcp")
	server, err = New(nil)
	require.NoError(t, err)
	assert.Equal(t, "tcp", server.auditTransport)

	viper.Reset()
	viper.Set("vault.audit_protocol", "invalid")
	logBuffer := new(bytes.Buffer)
	logger := slog.New(slog.NewTextHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, err = New(logger)
	require.NoError(t, err)
	assert.Equal(t, "udp", server.auditTransport)
	assert.Contains(t, logBuffer.String(), "Invalid vault.audit_protocol")
}

func TestNew_AsyncEnqueueModeBlankFallsBackToDrop(t *testing.T) {
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{})
	viper.Set("async.enqueue_mode", "   ")

	server, err := New(nil)
	require.NoError(t, err)
	assert.Equal(t, "drop", server.asyncEnqueueMode)
}

func TestNew_WithSlackMessengerAndDurableEnabled(t *testing.T) {
	viper.Reset()
	viper.Set("async.durable.enabled", true)
	viper.Set("async.durable.dir", t.TempDir())
	viper.Set("async.timeout", "17ms")
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "slack_group",
			"rules": []string{
				"true",
			},
			"log_file": map[string]interface{}{
				"file_path": filepath.Join(t.TempDir(), "slack.log"),
				"max_size":  1,
			},
			"messaging": map[string]interface{}{
				"type":    "slack",
				"url":     "https://example.invalid",
				"token":   "tok",
				"channel": "chan",
			},
		},
	})

	server, err := New(nil)
	require.NoError(t, err)
	require.NotNil(t, server.sideStore)
	require.True(t, server.asyncDurableEnabled)
	require.Len(t, server.ruleGroups, 1)
	require.NotNil(t, server.ruleGroups[0].Messenger)
}

func TestNew_DurableStoreCreationFailure(t *testing.T) {
	viper.Reset()
	viper.Set("async.durable.enabled", true)
	badBase := filepath.Join(t.TempDir(), "base-file")
	require.NoError(t, os.WriteFile(badBase, []byte("x"), 0o600))
	viper.Set("async.durable.dir", badBase)
	viper.Set("rule_groups", []map[string]interface{}{})

	server, err := New(nil)
	require.Error(t, err)
	assert.Nil(t, server)
	assert.Contains(t, err.Error(), "failed to create durable side task store")
}

func TestEnqueueSide_WaitMode_DefaultTimeoutBranch(t *testing.T) {
	as := &AuditServer{
		sideQueue:           make(chan sideTask, 1),
		asyncEnqueueMode:    "wait",
		asyncEnqueueTimeout: 0,
	}
	as.sideQueue <- sideTask{}

	start := time.Now()
	ok := as.enqueueSide(sideTask{})
	elapsed := time.Since(start)

	assert.False(t, ok)
	assert.GreaterOrEqual(t, elapsed, 4*time.Millisecond)
	assert.Equal(t, uint64(1), as.sideDrops.Load())
}

func TestProcessSideTask_RetrySaveErrorBranch(t *testing.T) {
	store := &errSideTaskStore{saveErr: errors.New("save failed")}
	as := &AuditServer{
		logger:                slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})),
		sideQueue:             make(chan sideTask, 1),
		asyncDurableEnabled:   true,
		asyncRetryMaxAttempts: 3,
		asyncRetryBackoff:     10 * time.Millisecond,
		sideStore:             store,
	}

	as.processSideTask(sideTask{
		id:         "task-r1",
		groupName:  "g",
		payload:    []byte("x"),
		payloadStr: "x",
		messenger:  &dummyMessenger{sendErr: errors.New("send failed")},
	})
}

func TestFileSideTaskStore_PendingReadDirAndReadFileBranches(t *testing.T) {
	store, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)

	// cover entries that are directories (continue branch)
	require.NoError(t, os.Mkdir(filepath.Join(store.pendingDir, "nested"), 0o755))
	_, err = store.Pending()
	require.NoError(t, err)

	// cover os.ReadFile error branch using broken symlink
	symlink := filepath.Join(store.pendingDir, "broken-link.json")
	require.NoError(t, os.Symlink(filepath.Join(store.pendingDir, "does-not-exist.json"), symlink))
	_, err = store.Pending()
	require.Error(t, err)

	// cover os.ReadDir error branch
	store.pendingDir = filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(store.pendingDir, []byte("x"), 0o600))
	_, err = store.Pending()
	require.Error(t, err)
}

func TestFileSideTaskStore_SaveAndMoveToDeadLetter_MarshalErrorBranches(t *testing.T) {
	store, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)

	origPersist := marshalPersistedSideTask
	origDead := marshalDeadLetterTask
	t.Cleanup(func() {
		marshalPersistedSideTask = origPersist
		marshalDeadLetterTask = origDead
	})

	marshalPersistedSideTask = func(p persistedSideTask) ([]byte, error) {
		_ = p
		return nil, errors.New("marshal persisted failed")
	}
	err = store.Save(sideTask{id: "save-1"})
	require.Error(t, err)

	marshalDeadLetterTask = func(d deadLetterTask) ([]byte, error) {
		_ = d
		return nil, errors.New("marshal dead failed")
	}
	err = store.MoveToDeadLetter(sideTask{id: "dead-1"}, "reason")
	require.Error(t, err)
}

type errSideTaskStore struct {
	mu          sync.Mutex
	saveErr     error
	deleteErr   error
	deadErr     error
	pendingErr  error
	pending     []sideTask
	saveCalls   int
	deleteCalls int
	deadCalls   int
}

func (s *errSideTaskStore) Save(task sideTask) error {
	s.mu.Lock()
	s.saveCalls++
	if s.saveErr == nil {
		s.pending = append(s.pending, task)
	}
	s.mu.Unlock()
	return s.saveErr
}

func (s *errSideTaskStore) Delete(id string) error {
	s.mu.Lock()
	s.deleteCalls++
	if s.deleteErr == nil && id != "" {
		filtered := s.pending[:0]
		for _, task := range s.pending {
			if task.id != id {
				filtered = append(filtered, task)
			}
		}
		s.pending = filtered
	}
	s.mu.Unlock()
	return s.deleteErr
}

func (s *errSideTaskStore) MoveToDeadLetter(task sideTask, reason string) error {
	s.mu.Lock()
	s.deadCalls++
	s.mu.Unlock()
	_ = task
	_ = reason
	return s.deadErr
}

func (s *errSideTaskStore) Pending() ([]sideTask, error) {
	if s.pendingErr != nil {
		return nil, s.pendingErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sideTask, len(s.pending))
	copy(out, s.pending)
	return out, nil
}

func TestNew_AsyncInvalidConfigFallsBackToDefaults(t *testing.T) {
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{})
	viper.Set("async.queue_size", 0)
	viper.Set("async.workers", -3)
	viper.Set("async.enqueue_mode", "invalid")
	viper.Set("async.enqueue_timeout", "not-a-duration")
	viper.Set("async.timeout", "also-bad")
	viper.Set("async.durable.enabled", false)
	viper.Set("async.durable.dir", "")
	viper.Set("async.retry.max_attempts", 0)
	viper.Set("async.retry.backoff", "bad")

	server, err := New(nil)
	require.NoError(t, err)
	require.NotNil(t, server)
	assert.Equal(t, 20, server.asyncQueueSize)
	assert.Equal(t, defaultSideWorkers, server.asyncWorkers)
	assert.Equal(t, "drop", server.asyncEnqueueMode)
	assert.Equal(t, 5*time.Millisecond, server.asyncEnqueueTimeout)
	assert.Equal(t, 5*time.Second, server.asyncTimeout)
	assert.Equal(t, "./.vault-audit-filter-sideeffects", server.asyncDurableDir)
	assert.Equal(t, 3, server.asyncRetryMaxAttempts)
	assert.Equal(t, 100*time.Millisecond, server.asyncRetryBackoff)
}

func TestEnqueueSide_DurableSaveFailureReturnsFalse(t *testing.T) {
	store := &errSideTaskStore{saveErr: errors.New("save failed")}
	as := &AuditServer{
		logger:              slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})),
		sideQueue:           make(chan sideTask, 1),
		asyncDurableEnabled: true,
		sideStore:           store,
	}

	ok := as.enqueueSide(sideTask{id: "task-1"})
	assert.False(t, ok)
	assert.Equal(t, uint64(0), as.sideDrops.Load())
}

func TestEnqueueSide_WaitMode_DurableTimeoutReturnsTrue(t *testing.T) {
	store := &errSideTaskStore{}
	as := &AuditServer{
		logger:              slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})),
		sideQueue:           make(chan sideTask, 1),
		asyncEnqueueMode:    "wait",
		asyncEnqueueTimeout: 2 * time.Millisecond,
		asyncDurableEnabled: true,
		asyncRetryBackoff:   1 * time.Millisecond,
		sideStore:           store,
	}
	as.sideQueue <- sideTask{id: "occupied"}

	ok := as.enqueueSide(sideTask{id: "task-2"})
	assert.True(t, ok)
	assert.Equal(t, uint64(0), as.sideDrops.Load())
}

func TestFileSideTaskStore_Branches(t *testing.T) {
	t.Run("new_store_errors", func(t *testing.T) {
		baseDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(baseDir, "deadletter"), []byte("x"), 0o600))
		_, err := newFileSideTaskStore(baseDir)
		require.Error(t, err)

		fileBase := filepath.Join(t.TempDir(), "base-file")
		require.NoError(t, os.WriteFile(fileBase, []byte("x"), 0o600))
		_, err = newFileSideTaskStore(fileBase)
		require.Error(t, err)
	})

	t.Run("save_delete_move_pending_edge_cases", func(t *testing.T) {
		store, err := newFileSideTaskStore(t.TempDir())
		require.NoError(t, err)

		assert.Error(t, store.Save(sideTask{}))
		assert.NoError(t, store.Delete(""))
		assert.NoError(t, store.Delete("missing"))
		assert.NoError(t, store.MoveToDeadLetter(sideTask{}, "ignored"))

		badFile := filepath.Join(store.pendingDir, "broken.json")
		require.NoError(t, os.WriteFile(badFile, []byte("{"), 0o600))
		_, err = store.Pending()
		require.Error(t, err)

		store.pendingDir = filepath.Join(t.TempDir(), "pending-file")
		require.NoError(t, os.WriteFile(store.pendingDir, []byte("x"), 0o600))
		err = store.Delete("id-1")
		require.Error(t, err)
	})
}

func TestReplayDurablePending_NoStoreOrPendingError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))

	asNoStore := &AuditServer{logger: logger}
	asNoStore.replayDurablePending()

	asErr := &AuditServer{
		logger:    logger,
		sideQueue: make(chan sideTask, 1),
		sideStore: &errSideTaskStore{pendingErr: errors.New("boom")},
	}
	asErr.replayDurablePending()
}

func TestOnTraffic(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("returns_close_when_next_fails", func(t *testing.T) {
		srv := &AuditServer{logger: logger}
		action := srv.OnTraffic(&fakeTrafficConn{err: errors.New("read failed")})
		require.Equal(t, gnet.Close, action)
	})

	t.Run("passes_frame_to_handler", func(t *testing.T) {
		srv := &AuditServer{
			logger:     logger,
			ruleGroups: []RuleGroup{{Name: "always", Writer: new(bytes.Buffer)}},
			sideQueue:  make(chan sideTask, 1),
		}

		action := srv.OnTraffic(&fakeTrafficConn{frame: auditFrame()})
		require.Equal(t, gnet.None, action)
	})
}

func TestOnTraffic_TCP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("complete frames clear context", func(t *testing.T) {
		buf := new(bytes.Buffer)
		srv := &AuditServer{
			logger:         logger,
			auditTransport: "tcp",
			ruleGroups:     []RuleGroup{{Name: "all", CompiledRules: nil, Writer: buf}},
			sideQueue:      make(chan sideTask, 1),
		}

		stream := append(auditFrame(), '\n')
		stream = append(stream, auditFrame()...)
		stream = append(stream, '\r', '\n')

		conn := &fakeTrafficConn{frame: stream}
		action := srv.OnTraffic(conn)

		require.Equal(t, gnet.None, action)
		require.NoError(t, conn.err)
		require.Nil(t, conn.Context())
		assert.Equal(t, 2, strings.Count(buf.String(), string(auditFrame())))
	})

	t.Run("partial frame keeps context", func(t *testing.T) {
		buf := new(bytes.Buffer)
		srv := &AuditServer{
			logger:         logger,
			auditTransport: "tcp",
			ruleGroups:     []RuleGroup{{Name: "all", CompiledRules: nil, Writer: buf}},
			sideQueue:      make(chan sideTask, 1),
		}

		line := auditFrame()
		half := len(line) / 2
		conn := &fakeTrafficConn{
			ctx:   append([]byte(nil), line[:half]...),
			frame: append(append([]byte(nil), line[half:]...), '\n'),
		}
		conn.frame = append(conn.frame, line...)

		action := srv.OnTraffic(conn)

		require.Equal(t, gnet.None, action)
		remaining, ok := conn.Context().([]byte)
		require.True(t, ok)
		assert.Equal(t, line, remaining)
		assert.Equal(t, 1, strings.Count(buf.String(), string(line)))
	})
}
