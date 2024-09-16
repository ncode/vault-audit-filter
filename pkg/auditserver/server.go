package auditserver

import (
	"bytes"
	"encoding/json"
	"github.com/panjf2000/gnet"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"os"
)

var (
	operationUpdate = []byte(`"operation":"update"`)
	operationCreate = []byte(`"operation":"create"`)
	operationDelete = []byte(`"operation":"delete"`)
	allowedPolicy   = []byte(`"policy_results":{"allowed":true`)
	mountTypeKV     = []byte(`"mount_type":"kv"`)
)

type Request struct {
	MountClass          string `json:"mount_class"`
	MountPoint          string `json:"mount_point"`
	MountRunningVersion string `json:"mount_running_version"`
	MountType           string `json:"mount_type"`
	Operation           string `json:"operation"`
	Path                string `json:"path"`
}

type Response struct {
	MountAccessor             string `json:"mount_accessor"`
	MountClass                string `json:"mount_class"`
	MountPoint                string `json:"mount_point"`
	MountRunningPluginVersion string `json:"mount_running_plugin_version"`
	MountType                 string `json:"mount_type"`
}

type Auth struct {
	Accessor      string `json:"accessor"`
	ClientToken   string `json:"client_token"`
	DisplayName   string `json:"display_name"`
	PolicyResults struct {
		Allowed bool `json:"allowed"`
	} `json:"policy_results"`
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

type AuditServer struct {
	*gnet.EventServer
	logger    *slog.Logger
	publisher *redis.Client
}

func (as *AuditServer) React(frame []byte, c gnet.Conn) (out []byte, action gnet.Action) {
	if !bytes.Contains(frame, mountTypeKV) {
		// Skip events that are not kv, we only care about kv at the moment
		return nil, gnet.Close
	}

	if !bytes.Contains(frame, allowedPolicy) {
		// Skip events that are not allowed
		return nil, gnet.Close
	}

	if !bytes.Contains(frame, operationUpdate) && !bytes.Contains(frame, operationCreate) && !bytes.Contains(frame, operationDelete) {
		// Skip events that are not relevant for courier
		return nil, gnet.Close
	}

	var auditLog AuditLog
	err := json.Unmarshal(frame, &auditLog)
	if err != nil {
		as.logger.Error("Error parsing audit log", "error", err)
		return nil, gnet.Close
	}

	if auditLog.Auth.PolicyResults.Allowed == true && auditLog.Response.MountType == "kv" {
		logAttrs := []any{
			"operation", auditLog.Request.Operation,
			"path", auditLog.Request.Path,
		}
		as.logger.Info("Received audit log", logAttrs...)
	}

	return
}

func New(logger *slog.Logger, publisher *redis.Client) *AuditServer {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if publisher == nil {
		publisher = redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
		})
	}
	return &AuditServer{
		logger: logger,
	}
}
