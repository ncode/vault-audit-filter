package auditserver

import (
	"fmt"
	json "github.com/bytedance/sonic"
	"io"
	"log"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/ncode/vault-audit-filter/pkg/forwarder"
	"github.com/ncode/vault-audit-filter/pkg/messaging"
	"github.com/panjf2000/gnet/v2"
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
	ruleExecutor          ruleGroupExecutor
	auditTransport        string
	sideQueue             chan sideTask
	sideDrops             atomic.Uint64
	sideProcessor         *sideEffectProcessor
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
	matchedIndexes = as.executor().Match(auditLog)
	result := matchResult{
		Matched:             len(matchedIndexes) > 0,
		Log:                 *auditLog,
		matchedGroupIndexes: matchedIndexes,
	}

	auditLogPool.Put(auditLog)
	return result, nil
}

func (as *AuditServer) handleFrameWithResult(frame []byte, result matchResult) {
	as.executor().Execute(frame, result.matchedGroupIndexes)
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
	return newTransportAdapter(as.auditTransport, as.logger, as).OnTraffic(c)
}

func (as *AuditServer) executor() ruleGroupExecutor {
	if as.ruleExecutor.groups != nil {
		return as.ruleExecutor
	}
	return newRuleGroupExecutor(as.ruleGroups, as.logger, as)
}

func (as *AuditServer) submitSideEffect(req sideEffectRequest) bool {
	if as.sideProcessor == nil {
		return false
	}
	return as.sideProcessor.Submit(req)
}

func (as *AuditServer) resolveSideTaskAdapters(groupName string) sideTaskAdapters {
	for i := range as.ruleGroups {
		if as.ruleGroups[i].Name == groupName {
			return sideTaskAdapters{
				messenger: as.ruleGroups[i].Messenger,
				forwarder: as.ruleGroups[i].Forwarder,
			}
		}
	}
	return sideTaskAdapters{}
}

func New(logger *slog.Logger, runtimeSettings ...RuntimeSettings) (*AuditServer, error) {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if len(runtimeSettings) > 1 {
		return nil, fmt.Errorf("expected at most one runtime settings value")
	}

	settings := DefaultRuntimeSettings()
	if len(runtimeSettings) == 1 {
		settings = runtimeSettings[0]
	}
	settings = NormalizeRuntimeSettings(settings, logger)

	var ruleGroups []RuleGroup
	if len(settings.RuleGroups) == 0 {
		defaultLogger := log.New(os.Stdout, "", 0)
		ruleGroups = append(ruleGroups, RuleGroup{
			Name:          "default",
			CompiledRules: nil,
			Logger:        defaultLogger,
		})
	} else {
		for _, rgConfig := range settings.RuleGroups {
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
				messenger = messaging.NewSlackMessenger(rgConfig.Messaging.URL, rgConfig.Messaging.Token, rgConfig.Messaging.Channel, settings.Async.Timeout)
			case "slack_webhook":
				messenger = messaging.NewSlackWebhookMessenger(rgConfig.Messaging.WebhookURL, settings.Async.Timeout)
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
					udpFwd.SetTimeout(settings.Async.Timeout)
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
		auditTransport:        settings.AuditProtocol,
		asyncEnqueueMode:      settings.Async.EnqueueMode,
		asyncEnqueueTimeout:   settings.Async.EnqueueTimeout,
		asyncWorkers:          settings.Async.Workers,
		asyncQueueSize:        settings.Async.QueueSize,
		asyncTimeout:          settings.Async.Timeout,
		asyncDurableEnabled:   settings.Async.Durable.Enabled,
		asyncDurableDir:       settings.Async.Durable.Dir,
		asyncRetryMaxAttempts: settings.Async.Retry.MaxAttempts,
		asyncRetryBackoff:     settings.Async.Retry.Backoff,
	}
	server.ruleExecutor = newRuleGroupExecutor(ruleGroups, logger, server)
	if settings.Async.Durable.Enabled {
		store, err := newFileSideTaskStore(settings.Async.Durable.Dir)
		if err != nil {
			return nil, fmt.Errorf("failed to create durable side task store: %w", err)
		}
		server.sideStore = store
	}
	server.sideProcessor = newSideEffectProcessor(sideEffectProcessorConfig{
		logger:               logger,
		queueSize:            settings.Async.QueueSize,
		enqueueMode:          settings.Async.EnqueueMode,
		enqueueTimeout:       settings.Async.EnqueueTimeout,
		durableEnabled:       settings.Async.Durable.Enabled,
		retryMaxAttempts:     settings.Async.Retry.MaxAttempts,
		retryBackoff:         settings.Async.Retry.Backoff,
		store:                server.sideStore,
		adapterResolver:      server.resolveSideTaskAdapters,
		mirrorDrops:          &server.sideDrops,
		mirrorTaskSeq:        &server.sideTaskSeq,
		mirrorQueue:          &server.sideQueue,
		mirrorEnqueueMode:    &server.asyncEnqueueMode,
		mirrorEnqueueTimeout: &server.asyncEnqueueTimeout,
	})
	server.sideProcessor.startWorkers(settings.Async.Workers)
	if settings.Async.Durable.Enabled {
		server.sideProcessor.replayDurablePending()
	}
	return server, nil
}
