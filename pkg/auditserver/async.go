package auditserver

import (
	"github.com/ncode/vault-audit-filter/pkg/forwarder"
	"github.com/ncode/vault-audit-filter/pkg/messaging"
)

var defaultSideWorkers = 2

type sideTask struct {
	payload    []byte
	payloadStr string
	messenger  messaging.Messenger
	forwarder  forwarder.Forwarder
}

func (as *AuditServer) enqueueSide(task sideTask) bool {
	select {
	case as.sideQueue <- task:
		return true
	default:
		as.sideDrops.Add(1)
		return false
	}
}

func (as *AuditServer) startSideWorkers(n int) {
	if n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		go func() {
			for task := range as.sideQueue {
				if task.messenger != nil {
					if err := task.messenger.Send(task.payloadStr); err != nil {
						as.logger.Error("Failed to send notification", "error", err)
					}
				}
				if task.forwarder != nil {
					if err := task.forwarder.Forward(task.payload); err != nil {
						as.logger.Error("Failed to forward message", "error", err)
					}
				}
			}
		}()
	}
}
