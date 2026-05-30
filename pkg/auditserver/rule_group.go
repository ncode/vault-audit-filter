package auditserver

import (
	"log/slog"

	"github.com/expr-lang/expr"
	"github.com/ncode/vault-audit-filter/pkg/forwarder"
	"github.com/ncode/vault-audit-filter/pkg/messaging"
)

type sideEffectRequest struct {
	groupName  string
	payload    []byte
	payloadStr string
	messenger  messaging.Messenger
	forwarder  forwarder.Forwarder
}

type sideEffectSubmitter interface {
	submitSideEffect(sideEffectRequest) bool
}

type ruleGroupExecutor struct {
	groups    []RuleGroup
	logger    *slog.Logger
	submitter sideEffectSubmitter
}

type ruleGroupPayload struct {
	frame           []byte
	payload         []byte
	payloadStr      string
	payloadReady    bool
	payloadStrReady bool
}

func newRuleGroupExecutor(groups []RuleGroup, logger *slog.Logger, submitter sideEffectSubmitter) ruleGroupExecutor {
	return ruleGroupExecutor{
		groups:    groups,
		logger:    logger,
		submitter: submitter,
	}
}

func (e ruleGroupExecutor) Match(auditLog *AuditLog) []int {
	var matchedIndexes []int
	for idx := range e.groups {
		if e.groups[idx].shouldLog(auditLog) {
			matchedIndexes = append(matchedIndexes, idx)
		}
	}
	return matchedIndexes
}

func (e ruleGroupExecutor) Execute(frame []byte, matchedIndexes []int) {
	payload := ruleGroupPayload{frame: frame}
	for _, idx := range matchedIndexes {
		if idx < 0 || idx >= len(e.groups) {
			continue
		}
		e.executeGroup(&e.groups[idx], &payload)
	}
}

func (e ruleGroupExecutor) executeGroup(rg *RuleGroup, payload *ruleGroupPayload) {
	if e.logger != nil {
		e.logger.Debug("Matched rule group", "group", rg.Name)
	}

	if (rg.Messenger != nil || rg.Forwarder != nil) && e.submitter != nil {
		payloadStr := ""
		if rg.Messenger != nil {
			payloadStr = payload.String()
		}
		e.submitter.submitSideEffect(sideEffectRequest{
			groupName:  rg.Name,
			payload:    payload.Bytes(),
			payloadStr: payloadStr,
			messenger:  rg.Messenger,
			forwarder:  rg.Forwarder,
		})
	}

	if rg.Writer != nil {
		if _, err := rg.Writer.Write(payload.frame); err != nil && e.logger != nil {
			e.logger.Error("Failed to write audit log", "group", rg.Name, "error", err)
		}
		return
	}

	rg.Logger.Print(payload.String())
}

func (p *ruleGroupPayload) Bytes() []byte {
	if !p.payloadReady {
		p.payload = append([]byte(nil), p.frame...)
		p.payloadReady = true
	}
	return p.payload
}

func (p *ruleGroupPayload) String() string {
	if !p.payloadStrReady {
		if p.payloadReady {
			p.payloadStr = string(p.payload)
		} else {
			p.payloadStr = string(p.frame)
		}
		p.payloadStrReady = true
	}
	return p.payloadStr
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
