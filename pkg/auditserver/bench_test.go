package auditserver

import (
	"io"
	"log/slog"
	"testing"

	"github.com/expr-lang/expr"
	"github.com/spf13/viper"
)

func BenchmarkReact(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "rg",
			"rules": []string{"true"},
			"log_file": map[string]interface{}{
				"file_path": "/tmp/test.log",
				"max_size":  1,
			},
		},
	})
	server, _ := New(logger)
	frame := []byte(`{"type":"request","time":"2000-01-01T00:00:00Z","auth":{},"request":{},"response":{}}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.React(frame, nil)
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
