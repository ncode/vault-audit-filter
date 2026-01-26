package auditserver

import (
	"fmt"
	json "github.com/bytedance/sonic"
	"io"
	"log"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/ncode/vault-audit-filter/pkg/forwarder"
	"github.com/ncode/vault-audit-filter/pkg/messaging"
	"github.com/panjf2000/gnet"
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
	*gnet.EventServer
	logger         *slog.Logger
	ruleGroups     []RuleGroup
	asyncQueueSize int
	asyncTimeout   time.Duration
}

func (as *AuditServer) React(frame []byte, c gnet.Conn) (out []byte, action gnet.Action) {
	// Parse the audit log for rule evaluation
	auditLog := auditLogPool.Get().(*AuditLog)
	*auditLog = AuditLog{} // reset pooled object

	err := json.Unmarshal(frame, auditLog)
	if err != nil {
		as.logger.Error("Error parsing audit log", "error", err)
		auditLogPool.Put(auditLog)
		return nil, gnet.Close
	}

	shouldClose := false
	matched := false
	forwarded := false

	// Check each rule group
	for _, rg := range as.ruleGroups {
		if rg.shouldLog(auditLog) {
			matched = true
			as.logger.Debug("Matched rule group", "group", rg.Name)

			// Send notification if messenger is configured
			if rg.Messenger != nil {
				if err := rg.Messenger.Send(string(frame)); err != nil {
					as.logger.Error("Failed to send notification", "error", err)
					shouldClose = true
				}
			}

			if rg.Forwarder != nil {
				if err := rg.Forwarder.Forward(frame); err != nil {
					as.logger.Error("Failed to forward message", "error", err)
					shouldClose = true
				}
				forwarded = true
			}

			// zero‑copy write to log when possible
			if rg.Writer != nil {
				if _, err := rg.Writer.Write(frame); err != nil {
					as.logger.Error("Failed to write audit log", "group", rg.Name, "error", err)
				}
			} else {
				rg.Logger.Print(string(frame))
			}
			// TODO(JM):Add a flag to prevent logging to multiple groups
			// break
		}
	}

	auditLogPool.Put(auditLog)

	// Preserve test expectations:
	// - Close on any messenger/forwarder error
	// - Close when no rule matched
	// - Close when a message was forwarded (original behaviour)
	if shouldClose || !matched || forwarded {
		return nil, gnet.Close
	}
	return nil, gnet.None
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

func New(logger *slog.Logger) (*AuditServer, error) {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	viper.SetDefault("async.queue_size", 20)
	viper.SetDefault("async.timeout", "5s")

	queueSize := viper.GetInt("async.queue_size")
	if queueSize <= 0 {
		queueSize = 20
	}
	rawTimeout := viper.GetString("async.timeout")
	asyncTimeout, err := time.ParseDuration(rawTimeout)
	if err != nil {
		asyncTimeout = 5 * time.Second
		logger.Warn("Invalid async.timeout; using default", "value", rawTimeout)
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
		return &AuditServer{
			logger:         logger,
			ruleGroups:     ruleGroups,
			asyncQueueSize: queueSize,
			asyncTimeout:   asyncTimeout,
		}, nil
	}
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
			messenger = messaging.NewSlackMessenger(rgConfig.Messaging.URL, rgConfig.Messaging.Token, rgConfig.Messaging.Channel)
		case "slack_webhook":
			messenger = messaging.NewSlackWebhookMessenger(rgConfig.Messaging.WebhookURL)
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

	return &AuditServer{
		logger:         logger,
		ruleGroups:     ruleGroups,
		asyncQueueSize: queueSize,
		asyncTimeout:   asyncTimeout,
	}, nil
}
