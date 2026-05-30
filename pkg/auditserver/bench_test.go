package auditserver

import (
	"io"
	"log/slog"
	"testing"

	"github.com/expr-lang/expr"
)

func BenchmarkReact(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	settings := testRuntimeSettings([]RuleGroupConfig{
		{
			Name:    "rg",
			Rules:   []string{"true"},
			LogFile: LogFileConfig{FilePath: "/tmp/test.log", MaxSize: 1},
		},
	})
	server, _ := New(logger, settings)
	frame := []byte(`{"type":"request","time":"2000-01-01T00:00:00Z","auth":{},"request":{},"response":{}}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.React(frame, nil)
	}
}

func BenchmarkMatchFrame(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	settings := testRuntimeSettings([]RuleGroupConfig{
		{
			Name:    "rg",
			Rules:   []string{"Auth.PolicyResults.Allowed == true"},
			LogFile: LogFileConfig{FilePath: "/tmp/test.log", MaxSize: 1},
		},
	})
	server, _ := New(logger, settings)
	frame := []byte(`{"type":"request","time":"2000-01-01T00:00:00Z","auth":{"policy_results":{"allowed":true}},"request":{},"response":{}}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := server.MatchFrame(frame)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkShouldLog(b *testing.B) {
	p, _ := expr.Compile("true", expr.Env(&AuditLog{}))
	rg := &RuleGroup{CompiledRules: []CompiledRule{{Program: p}}}
	al := &AuditLog{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rg.shouldLog(al)
	}
}
