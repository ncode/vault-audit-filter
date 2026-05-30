package cmd

import (
	"fmt"
	"time"

	"github.com/ncode/vault-audit-filter/pkg/auditserver"
	"github.com/spf13/viper"
)

func auditServerRuntimeSettings() (auditserver.RuntimeSettings, error) {
	defaults := auditserver.DefaultRuntimeSettings()
	setAuditServerDefaults(defaults)

	var ruleGroups []auditserver.RuleGroupConfig
	if err := viper.UnmarshalKey("rule_groups", &ruleGroups); err != nil {
		logger.Error("Failed to load rule groups", "error", err)
		return auditserver.RuntimeSettings{}, fmt.Errorf("failed to load rule groups: %w", err)
	}

	protocol, err := vaultAuditProtocol()
	if err != nil {
		return auditserver.RuntimeSettings{}, err
	}

	settings := defaults
	settings.RuleGroups = ruleGroups
	settings.AuditProtocol = protocol
	settings.Async.QueueSize = viper.GetInt("async.queue_size")
	settings.Async.Workers = viper.GetInt("async.workers")
	settings.Async.EnqueueMode = viper.GetString("async.enqueue_mode")
	settings.Async.EnqueueTimeout = durationSetting("async.enqueue_timeout", defaults.Async.EnqueueTimeout)
	settings.Async.Timeout = durationSetting("async.timeout", defaults.Async.Timeout)
	settings.Async.Durable.Enabled = viper.GetBool("async.durable.enabled")
	settings.Async.Durable.Dir = viper.GetString("async.durable.dir")
	settings.Async.Retry.MaxAttempts = viper.GetInt("async.retry.max_attempts")
	settings.Async.Retry.Backoff = durationSetting("async.retry.backoff", defaults.Async.Retry.Backoff)

	return auditserver.NormalizeRuntimeSettings(settings, logger), nil
}

func setAuditServerDefaults(defaults auditserver.RuntimeSettings) {
	viper.SetDefault("async.queue_size", defaults.Async.QueueSize)
	viper.SetDefault("async.workers", defaults.Async.Workers)
	viper.SetDefault("async.enqueue_mode", defaults.Async.EnqueueMode)
	viper.SetDefault("async.enqueue_timeout", defaults.Async.EnqueueTimeout.String())
	viper.SetDefault("async.timeout", defaults.Async.Timeout.String())
	viper.SetDefault("async.durable.enabled", defaults.Async.Durable.Enabled)
	viper.SetDefault("async.durable.dir", defaults.Async.Durable.Dir)
	viper.SetDefault("async.retry.max_attempts", defaults.Async.Retry.MaxAttempts)
	viper.SetDefault("async.retry.backoff", defaults.Async.Retry.Backoff.String())
}

func durationSetting(key string, fallback time.Duration) time.Duration {
	raw := viper.GetString(key)
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		logger.Warn("Invalid duration config; using default", "key", key, "value", raw)
		return fallback
	}
	return value
}
