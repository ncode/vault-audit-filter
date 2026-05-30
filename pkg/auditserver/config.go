package auditserver

import (
	"log/slog"
	"strings"
	"time"
)

const (
	defaultAsyncQueueSize      = 20
	defaultAsyncEnqueueMode    = "drop"
	defaultAsyncEnqueueTimeout = 5 * time.Millisecond
	defaultAsyncTimeout        = 5 * time.Second
	defaultDurableDir          = "./.vault-audit-filter-sideeffects"
	defaultRetryMaxAttempts    = 3
	defaultRetryBackoff        = 100 * time.Millisecond
	defaultAuditProtocol       = "udp"
)

type RuntimeSettings struct {
	RuleGroups    []RuleGroupConfig
	Async         AsyncSettings
	AuditProtocol string
}

type AsyncSettings struct {
	QueueSize      int
	Workers        int
	EnqueueMode    string
	EnqueueTimeout time.Duration
	Timeout        time.Duration
	Durable        DurableSettings
	Retry          RetrySettings
}

type DurableSettings struct {
	Enabled bool
	Dir     string
}

type RetrySettings struct {
	MaxAttempts int
	Backoff     time.Duration
}

func DefaultRuntimeSettings() RuntimeSettings {
	return RuntimeSettings{
		AuditProtocol: defaultAuditProtocol,
		Async: AsyncSettings{
			QueueSize:      defaultAsyncQueueSize,
			Workers:        defaultSideWorkers,
			EnqueueMode:    defaultAsyncEnqueueMode,
			EnqueueTimeout: defaultAsyncEnqueueTimeout,
			Timeout:        defaultAsyncTimeout,
			Durable: DurableSettings{
				Enabled: false,
				Dir:     defaultDurableDir,
			},
			Retry: RetrySettings{
				MaxAttempts: defaultRetryMaxAttempts,
				Backoff:     defaultRetryBackoff,
			},
		},
	}
}

func NormalizeRuntimeSettings(settings RuntimeSettings, logger *slog.Logger) RuntimeSettings {
	defaults := DefaultRuntimeSettings()

	protocol := strings.ToLower(strings.TrimSpace(settings.AuditProtocol))
	switch protocol {
	case "":
		settings.AuditProtocol = defaults.AuditProtocol
	case "udp", "tcp":
		settings.AuditProtocol = protocol
	default:
		warnConfigFallback(logger, "Invalid vault.audit_protocol; using udp", "value", protocol)
		settings.AuditProtocol = defaults.AuditProtocol
	}

	if settings.Async.QueueSize <= 0 {
		settings.Async.QueueSize = defaults.Async.QueueSize
	}
	if settings.Async.Workers < 0 {
		settings.Async.Workers = defaults.Async.Workers
	}

	enqueueMode := strings.ToLower(strings.TrimSpace(settings.Async.EnqueueMode))
	switch enqueueMode {
	case "":
		settings.Async.EnqueueMode = defaults.Async.EnqueueMode
	case "drop", "wait":
		settings.Async.EnqueueMode = enqueueMode
	default:
		warnConfigFallback(logger, "Invalid async.enqueue_mode; using default", "value", enqueueMode)
		settings.Async.EnqueueMode = defaults.Async.EnqueueMode
	}

	if settings.Async.EnqueueTimeout <= 0 {
		warnConfigFallback(logger, "Invalid async.enqueue_timeout; using default", "value", settings.Async.EnqueueTimeout.String())
		settings.Async.EnqueueTimeout = defaults.Async.EnqueueTimeout
	}
	if settings.Async.Timeout <= 0 {
		warnConfigFallback(logger, "Invalid async.timeout; using default", "value", settings.Async.Timeout.String())
		settings.Async.Timeout = defaults.Async.Timeout
	}

	durableDir := strings.TrimSpace(settings.Async.Durable.Dir)
	if durableDir == "" {
		settings.Async.Durable.Dir = defaults.Async.Durable.Dir
	} else {
		settings.Async.Durable.Dir = durableDir
	}

	if settings.Async.Retry.MaxAttempts <= 0 {
		settings.Async.Retry.MaxAttempts = defaults.Async.Retry.MaxAttempts
	}
	if settings.Async.Retry.Backoff <= 0 {
		warnConfigFallback(logger, "Invalid async.retry.backoff; using default", "value", settings.Async.Retry.Backoff.String())
		settings.Async.Retry.Backoff = defaults.Async.Retry.Backoff
	}

	return settings
}

func warnConfigFallback(logger *slog.Logger, msg string, args ...any) {
	if logger != nil {
		logger.Warn(msg, args...)
	}
}
