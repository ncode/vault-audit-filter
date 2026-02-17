package auditserver

import (
	"bytes"
	"fmt"
	json "github.com/bytedance/sonic"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/ncode/vault-audit-filter/pkg/forwarder"
	"github.com/ncode/vault-audit-filter/pkg/messaging"
	"github.com/panjf2000/gnet/v2"
	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
)

// reuse objects to slash allocations
var auditLogPool = sync.Pool{
	New: func() any { return new(AuditLog) },
}

type Request struct {
	ID                  string `json:"id"`
	ClientID            string `json:"client_id"`
	Operation           string `json:"operation"`
	MountPoint          string `json:"mount_point"`
	MountType           string `json:"mount_type"`
	MountAccessor       string `json:"mount_accessor"`
	MountRunningVersion string `json:"mount_running_version"`
	MountClass          string `json:"mount_class"`
	ClientToken         string `json:"client_token"`
	ClientTokenAccessor string `json:"client_token_accessor"`
	Path                string `json:"path"`
	RemoteAddress       string `json:"remote_address"`
	RemotePort          int    `json:"remote_port"`
}

type Response struct {
	MountPoint                string `json:"mount_point"`
	MountType                 string `json:"mount_type"`
	MountAccessor             string `json:"mount_accessor"`
	MountRunningPluginVersion string `json:"mount_running_plugin_version"`
	MountClass                string `json:"mount_class"`
	Data                      struct {
		CasRequired        bool   `json:"cas_required"`
		CreatedTime        string `json:"created_time"`
		CurrentVersion     int    `json:"current_version"`
		DeleteVersionAfter string `json:"delete_version_after"`
		MaxVersions        int    `json:"max_versions"`
		OldestVersion      int    `json:"oldest_version"`
		UpdatedTime        string `json:"updated_time"`
	} `json:"data"`
}

type Auth struct {
	ClientToken   string   `json:"client_token"`
	Accessor      string   `json:"accessor"`
	DisplayName   string   `json:"display_name"`
	Policies      []string `json:"policies"`
	TokenPolicies []string `json:"token_policies"`
	PolicyResults struct {
		Allowed          bool `json:"allowed"`
		GrantingPolicies []struct {
			Name        string `json:"name"`
			NamespaceID string `json:"namespace_id"`
			Type        string `json:"type"`
		} `json:"granting_policies"`
	} `json:"policy_results"`
	TokenType      string    `json:"token_type"`
	TokenIssueTime time.Time `json:"token_issue_time"`
}

type AuditLog struct {
	Type       string   `json:"type"`
	Time       string   `json:"time"`
	Auth       Auth     `json:"auth"`
	Request    Request  `json:"request"`
	Response   Response `json:"response"`
	Error      string   `json:"error"`
	RemoteAddr string   `json:"remote_addr"`
}

type CompiledRule struct {
	Program *vm.Program
}

type RuleGroup struct {
	Name          string
	CompiledRules []CompiledRule
	Logger        *log.Logger
	Messenger     messaging.Messenger
	Forwarder     forwarder.Forwarder
	Writer        io.Writer
}

type Messaging struct {
	Type       string `mapstructure:"type"`
	Token      string `mapstructure:"token"`
	Channel    string `mapstructure:"channel"`
	URL        string `mapstructure:"url"`
	WebhookURL string `mapstructure:"webhook_url"`
}

type ForwardingConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Address string `mapstructure:"address"`
}

type RuleGroupConfig struct {
	Name       string           `mapstructure:"name"`
	Rules      []string         `mapstructure:"rules"`
	LogFile    LogFileConfig    `mapstructure:"log_file"`
	Messaging  Messaging        `mapstructure:"messaging"`
	Forwarding ForwardingConfig `mapstructure:"forwarding"`
}

type LogFileConfig struct {
	FilePath   string `mapstructure:"file_path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
}

type AuditServer struct {
	*gnet.BuiltinEventEngine
	logger                *slog.Logger
	ruleGroups            []RuleGroup
	auditTransport        string
	sideQueue             chan sideTask
	sideDrops             atomic.Uint64
	asyncEnqueueMode      string
	asyncEnqueueTimeout   time.Duration
	asyncWorkers          int
	asyncQueueSize        int
	asyncTimeout          time.Duration
	asyncDurableEnabled   bool
	asyncDurableDir       string
	asyncRetryMaxAttempts int
	asyncRetryBackoff     time.Duration
	sideStore             sideTaskStore
	sideTaskSeq           atomic.Uint64
}

// MatchResult describes the outcome of matching a single audit frame.
// It mirrors the rule-group matching behavior used by the runtime event loop,
// returning the decoded log and any rule groups that matched.
type MatchResult struct {
	Matched       bool
	Log           AuditLog
	MatchedGroups []string
}

type matchResult struct {
	Matched             bool
	Log                 AuditLog
	matchedGroupIndexes []int
}

// MatchFrame evaluates a raw audit log frame against configured rule groups.
// It returns whether any group matched, the decoded audit log, and the names of
// matching rule groups in configured order.
func (as *AuditServer) MatchFrame(frame []byte) (MatchResult, error) {
	result, err := as.matchFrame(frame)
	if err != nil {
		return MatchResult{}, err
	}

	matchedGroups := make([]string, 0, len(result.matchedGroupIndexes))
	for _, idx := range result.matchedGroupIndexes {
		matchedGroups = append(matchedGroups, as.ruleGroups[idx].Name)
	}

	return MatchResult{
		Matched:       result.Matched,
		Log:           result.Log,
		MatchedGroups: matchedGroups,
	}, nil
}

func (as *AuditServer) matchFrame(frame []byte) (matchResult, error) {
	auditLog := auditLogPool.Get().(*AuditLog)
	*auditLog = AuditLog{}

	err := json.Unmarshal(frame, auditLog)
	if err != nil {
		auditLogPool.Put(auditLog)
		return matchResult{}, err
	}

	var matchedIndexes []int
	for idx := range as.ruleGroups {
		if as.ruleGroups[idx].shouldLog(auditLog) {
			matchedIndexes = append(matchedIndexes, idx)
		}
	}
	result := matchResult{
		Matched:             len(matchedIndexes) > 0,
		Log:                 *auditLog,
		matchedGroupIndexes: matchedIndexes,
	}

	auditLogPool.Put(auditLog)
	return result, nil
}

func (as *AuditServer) handleFrameWithResult(frame []byte, result matchResult) {

	var payload []byte
	var payloadStr string
	payloadReady := false
	payloadStrReady := false

	for _, rgIdx := range result.matchedGroupIndexes {
		rg := as.ruleGroups[rgIdx]

		as.logger.Debug("Matched rule group", "group", rg.Name)

		if rg.Messenger != nil || rg.Forwarder != nil {
			if !payloadReady {
				payload = append([]byte(nil), frame...)
				payloadReady = true
			}
			if rg.Messenger != nil && !payloadStrReady {
				payloadStr = string(payload)
				payloadStrReady = true
			}
			_ = as.enqueueSide(sideTask{
				groupName:  rg.Name,
				payload:    payload,
				payloadStr: payloadStr,
				messenger:  rg.Messenger,
				forwarder:  rg.Forwarder,
			})
		}

		if rg.Writer != nil {
			if _, err := rg.Writer.Write(frame); err != nil {
				as.logger.Error("Failed to write audit log", "group", rg.Name, "error", err)
			}
		} else {
			if payloadStrReady {
				rg.Logger.Print(payloadStr)
			} else {
				rg.Logger.Print(string(frame))
			}
		}
	}
}

func (as *AuditServer) handleFrame(frame []byte) gnet.Action {
	result, err := as.matchFrame(frame)
	if err != nil {
		as.logger.Error("Error parsing audit log", "error", err)
		return gnet.Close
	}
	if !result.Matched {
		return gnet.Close
	}

	as.handleFrameWithResult(frame, result)

	return gnet.None
}

func (as *AuditServer) React(frame []byte, _ gnet.Conn) (out []byte, action gnet.Action) {
	return nil, as.handleFrame(frame)
}

func (as *AuditServer) OnTraffic(c gnet.Conn) (action gnet.Action) {
	frame, err := c.Next(-1)
	if err != nil {
		as.logger.Error("Error reading frame", "error", err)
		return gnet.Close
	}
	if as.auditTransport == "tcp" {
		var carryover []byte
		if ctx := c.Context(); ctx != nil {
			if b, ok := ctx.([]byte); ok {
				carryover = b
			}
		}

		remaining := as.handleTCPStream(frame, carryover)
		if len(remaining) == 0 {
			c.SetContext(nil)
			return gnet.None
		}
		c.SetContext(append([]byte(nil), remaining...))
		return gnet.None
	}
	return as.handleFrame(frame)
}

func (as *AuditServer) handleTCPStream(frame []byte, carryover []byte) []byte {
	buffer := append([]byte(nil), carryover...)
	if len(frame) > 0 {
		buffer = append(buffer, frame...)
	}

	for {
		sep := bytes.IndexByte(buffer, '\n')
		if sep < 0 {
			return buffer
		}

		rawLine := buffer[:sep]
		line := bytes.TrimSuffix(rawLine, []byte{'\r'})
		if len(line) > 0 {
			_ = as.handleFrame(line)
		}

		if sep == len(buffer)-1 {
			buffer = buffer[:0]
		} else {
			buffer = buffer[sep+1:]
		}
	}
}

func (rg *RuleGroup) shouldLog(auditLog *AuditLog) bool {
	if len(rg.CompiledRules) == 0 {
		return true
	}
	for _, compiledRule := range rg.CompiledRules {
		output, err := expr.Run(compiledRule.Program, auditLog)
		if err != nil {
			continue
		}
		if match, ok := output.(bool); ok && match {
			return true
		}
	}
	return false
}

func auditTransportProtocol(logger *slog.Logger) string {
	protocol := strings.ToLower(strings.TrimSpace(viper.GetString("vault.audit_protocol")))
	if protocol == "" {
		protocol = "udp"
	}

	switch protocol {
	case "udp", "tcp":
		return protocol
	default:
		if logger != nil {
			logger.Warn("Invalid vault.audit_protocol; using udp", "value", protocol)
		}
		return "udp"
	}
}

func New(logger *slog.Logger) (*AuditServer, error) {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	viper.SetDefault("async.queue_size", 20)
	viper.SetDefault("async.workers", defaultSideWorkers)
	viper.SetDefault("async.enqueue_mode", "drop")
	viper.SetDefault("async.enqueue_timeout", "5ms")
	viper.SetDefault("async.timeout", "5s")
	viper.SetDefault("async.durable.enabled", false)
	viper.SetDefault("async.durable.dir", "./.vault-audit-filter-sideeffects")
	viper.SetDefault("async.retry.max_attempts", 3)
	viper.SetDefault("async.retry.backoff", "100ms")

	queueSize := viper.GetInt("async.queue_size")
	if queueSize <= 0 {
		queueSize = 20
	}
	workers := viper.GetInt("async.workers")
	if workers < 0 {
		workers = defaultSideWorkers
	}
	enqueueMode := strings.ToLower(strings.TrimSpace(viper.GetString("async.enqueue_mode")))
	if enqueueMode == "" {
		enqueueMode = "drop"
	}
	if enqueueMode != "drop" && enqueueMode != "wait" {
		logger.Warn("Invalid async.enqueue_mode; using default", "value", enqueueMode)
		enqueueMode = "drop"
	}
	rawEnqueueTimeout := viper.GetString("async.enqueue_timeout")
	enqueueTimeout, err := time.ParseDuration(rawEnqueueTimeout)
	if err != nil || enqueueTimeout <= 0 {
		enqueueTimeout = 5 * time.Millisecond
		logger.Warn("Invalid async.enqueue_timeout; using default", "value", rawEnqueueTimeout)
	}
	rawTimeout := viper.GetString("async.timeout")
	asyncTimeout, err := time.ParseDuration(rawTimeout)
	if err != nil {
		asyncTimeout = 5 * time.Second
		logger.Warn("Invalid async.timeout; using default", "value", rawTimeout)
	}
	durableEnabled := viper.GetBool("async.durable.enabled")
	durableDir := strings.TrimSpace(viper.GetString("async.durable.dir"))
	if durableDir == "" {
		durableDir = "./.vault-audit-filter-sideeffects"
	}
	retryMaxAttempts := viper.GetInt("async.retry.max_attempts")
	if retryMaxAttempts <= 0 {
		retryMaxAttempts = 3
	}
	rawRetryBackoff := viper.GetString("async.retry.backoff")
	retryBackoff, err := time.ParseDuration(rawRetryBackoff)
	if err != nil || retryBackoff <= 0 {
		retryBackoff = 100 * time.Millisecond
		logger.Warn("Invalid async.retry.backoff; using default", "value", rawRetryBackoff)
	}

	// Load rule groups from configuration
	var ruleGroupConfigs []RuleGroupConfig
	if err := viper.UnmarshalKey("rule_groups", &ruleGroupConfigs); err != nil {
		logger.Error("Failed to load rule groups", "error", err)
		return nil, fmt.Errorf("failed to load rule groups: %w", err)
	}

	var ruleGroups []RuleGroup
	if len(ruleGroupConfigs) == 0 {
		defaultLogger := log.New(os.Stdout, "", 0)
		ruleGroups = append(ruleGroups, RuleGroup{
			Name:          "default",
			CompiledRules: nil,
			Logger:        defaultLogger,
		})
	} else {
		for _, rgConfig := range ruleGroupConfigs {
			// Compile rules
			var compiledRules []CompiledRule
			for _, ruleStr := range rgConfig.Rules {
				program, err := expr.Compile(ruleStr, expr.Env(&AuditLog{}))
				if err != nil {
					logger.Error("Failed to compile rule", "rule", ruleStr, "error", err)
					continue
				}
				compiledRules = append(compiledRules, CompiledRule{Program: program})
			}

			// Logger for group
			logFileCfg := rgConfig.LogFile
			logFile := &lumberjack.Logger{
				Filename:   logFileCfg.FilePath,
				MaxSize:    logFileCfg.MaxSize,
				MaxBackups: logFileCfg.MaxBackups,
				MaxAge:     logFileCfg.MaxAge,
				Compress:   logFileCfg.Compress,
			}
			groupLogger := log.New(logFile, "", 0)

			// Messenger
			var messenger messaging.Messenger
			switch rgConfig.Messaging.Type {
			case "slack":
				messenger = messaging.NewSlackMessenger(rgConfig.Messaging.URL, rgConfig.Messaging.Token, rgConfig.Messaging.Channel, asyncTimeout)
			case "slack_webhook":
				messenger = messaging.NewSlackWebhookMessenger(rgConfig.Messaging.WebhookURL, asyncTimeout)
			default:
				if rgConfig.Messaging.Type != "" {
					logger.Error("Invalid messenger type", "type", rgConfig.Messaging.Type)
				}
			}

			// Forwarder
			var fwd forwarder.Forwarder
			if rgConfig.Forwarding.Enabled {
				var err error
				fwd, err = forwarder.NewUDPForwarder(rgConfig.Forwarding.Address)
				if err != nil {
					logger.Error("Failed to create UDP forwarder", "error", err)
					return nil, fmt.Errorf("failed to create UDP forwarder: %w", err)
				}
				if udpFwd, ok := fwd.(*forwarder.UDPForwarder); ok {
					udpFwd.SetTimeout(asyncTimeout)
				}
			}

			ruleGroups = append(ruleGroups, RuleGroup{
				Name:          rgConfig.Name,
				CompiledRules: compiledRules,
				Logger:        groupLogger,
				Writer:        logFile,
				Messenger:     messenger,
				Forwarder:     fwd,
			})
		}
	}

	server := &AuditServer{
		logger:                logger,
		ruleGroups:            ruleGroups,
		auditTransport:        auditTransportProtocol(logger),
		sideQueue:             make(chan sideTask, queueSize),
		asyncEnqueueMode:      enqueueMode,
		asyncEnqueueTimeout:   enqueueTimeout,
		asyncWorkers:          workers,
		asyncQueueSize:        queueSize,
		asyncTimeout:          asyncTimeout,
		asyncDurableEnabled:   durableEnabled,
		asyncDurableDir:       durableDir,
		asyncRetryMaxAttempts: retryMaxAttempts,
		asyncRetryBackoff:     retryBackoff,
	}
	if durableEnabled {
		store, err := newFileSideTaskStore(durableDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create durable side task store: %w", err)
		}
		server.sideStore = store
	}
	server.startSideWorkers(workers)
	if durableEnabled {
		server.replayDurablePending()
	}
	return server, nil
}
