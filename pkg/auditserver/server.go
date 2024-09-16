package auditserver

import (
	"encoding/json"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/panjf2000/gnet"
	"github.com/spf13/viper"
	"log/slog"
	"os"
	"time"
)

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
		CreatedTime    string            `json:"created_time"`
		CustomMetadata map[string]string `json:"custom_metadata"`
		DeletionTime   string            `json:"deletion_time"`
		Destroyed      bool              `json:"destroyed"`
		Version        int               `json:"version"`
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

type AuditServer struct {
	*gnet.EventServer
	logger       *slog.Logger
	compiledExpr []CompiledRule
}

func (as *AuditServer) React(frame []byte, c gnet.Conn) (out []byte, action gnet.Action) {
	// Parse the audit log
	var auditLog AuditLog
	err := json.Unmarshal(frame, &auditLog)
	if err != nil {
		as.logger.Error("Error parsing audit log", "error", err)
		return nil, gnet.Close
	}

	// Apply the rules using expr
	if as.shouldLog(&auditLog) {
		logAttrs := []any{
			"operation", auditLog.Request.Operation,
			"path", auditLog.Request.Path,
			"user", auditLog.Auth.DisplayName,
			"client_id", auditLog.Request.ClientID,
			"remote_addr", auditLog.Request.RemoteAddress,
			"time", auditLog.Time,
		}
		as.logger.Info("Received audit log", logAttrs...)
	}

	return nil, gnet.Close
}
func (as *AuditServer) shouldLog(auditLog *AuditLog) bool {
	// If no rules are defined, log all audit logs
	if len(as.compiledExpr) == 0 {
		return true
	}

	for _, compiledRule := range as.compiledExpr {
		output, err := expr.Run(compiledRule.Program, auditLog)
		if err != nil {
			as.logger.Error("Error evaluating rule", "error", err)
			continue
		}
		if match, ok := output.(bool); ok && match {
			return true
		}
	}
	return false
}

func New(logger *slog.Logger) *AuditServer {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	// Load and compile rules from configuration
	var ruleStrings []string
	if err := viper.UnmarshalKey("rules", &ruleStrings); err != nil {
		logger.Error("Failed to load rules", "error", err)
	}

	var compiledExpr []CompiledRule
	for _, ruleStr := range ruleStrings {
		program, err := expr.Compile(ruleStr, expr.Env(&AuditLog{}))
		if err != nil {
			logger.Error("Failed to compile rule", "rule", ruleStr, "error", err)
			continue
		}
		compiledExpr = append(compiledExpr, CompiledRule{Program: program})
	}

	return &AuditServer{
		logger:       logger,
		compiledExpr: compiledExpr,
	}
}
