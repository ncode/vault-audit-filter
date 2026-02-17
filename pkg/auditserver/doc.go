// Package auditserver provides Vault audit log filtering and side-effect processing.
//
// In library mode, callers can construct a server with `New`, then call `MatchFrame`
// to evaluate a raw audit log frame without running a gnet event loop.
//
// Example:
//
//	server, err := New(nil)
//	if err != nil {
//		// handle init error
//	}
//	result, err := server.MatchFrame([]byte("{\"type\":\"request\",\"time\":\"2024-01-01T00:00:00Z\",\"request\":{\"operation\":\"update\",\"path\":\"secret/data/config\"},\"auth\":{\"policy_results\":{\"allowed\":true}}}"))
//	if err != nil {
//		// handle parse error
//	}
//	if result.Matched {
//		// result.Log holds the parsed AuditLog
//		// result.MatchedGroups lists matched rule group names
//	}
package auditserver
