package auditserver

import (
	"strconv"
	"time"

	"github.com/ncode/vault-audit-filter/pkg/forwarder"
	"github.com/ncode/vault-audit-filter/pkg/messaging"
)

var defaultSideWorkers = 2

type sideTask struct {
	id         string
	groupName  string
	attempts   int
	payload    []byte
	payloadStr string
	messenger  messaging.Messenger
	forwarder  forwarder.Forwarder
}

func (as *AuditServer) enqueueSide(task sideTask) bool {
	if as.asyncDurableEnabled && as.sideStore != nil {
		if task.id == "" {
			task.id = as.nextSideTaskID()
		}
		if err := as.sideStore.Save(task); err != nil {
			as.logger.Error("Failed to persist durable side task", "error", err)
			return false
		}
	}

	if as.asyncEnqueueMode == "wait" {
		timeout := as.asyncEnqueueTimeout
		if timeout <= 0 {
			timeout = 5 * time.Millisecond
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case as.sideQueue <- task:
			return true
		case <-timer.C:
			if as.asyncDurableEnabled {
				time.AfterFunc(as.asyncRetryBackoff, func() {
					_ = as.enqueueSide(task)
				})
				return true
			}
			as.sideDrops.Add(1)
			return false
		}
	}

	select {
	case as.sideQueue <- task:
		return true
	default:
		if as.asyncDurableEnabled {
			time.AfterFunc(as.asyncRetryBackoff, func() {
				_ = as.enqueueSide(task)
			})
			return true
		}
		as.sideDrops.Add(1)
		return false
	}
}

func (as *AuditServer) nextSideTaskID() string {
	n := as.sideTaskSeq.Add(1)
	return time.Now().Format("20060102150405.000000000") + "-" + strconv.FormatUint(n, 10)
}

func (as *AuditServer) startSideWorkers(n int) {
	if n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		go func() {
			for task := range as.sideQueue {
				as.processSideTask(task)
			}
		}()
	}
}

func (as *AuditServer) processSideTask(task sideTask) {
	messenger := task.messenger
	fwd := task.forwarder
	if task.groupName != "" {
		for i := range as.ruleGroups {
			if as.ruleGroups[i].Name == task.groupName {
				if messenger == nil {
					messenger = as.ruleGroups[i].Messenger
				}
				if fwd == nil {
					fwd = as.ruleGroups[i].Forwarder
				}
				break
			}
		}
	}

	var sendErr error
	if messenger != nil {
		if err := messenger.Send(task.payloadStr); err != nil {
			as.logger.Error("Failed to send notification", "error", err)
			sendErr = err
		}
	}
	if fwd != nil {
		if err := fwd.Forward(task.payload); err != nil {
			as.logger.Error("Failed to forward message", "error", err)
			if sendErr == nil {
				sendErr = err
			}
		}
	}

	if !as.asyncDurableEnabled || as.sideStore == nil || task.id == "" {
		return
	}

	if sendErr == nil {
		_ = as.sideStore.Delete(task.id)
		return
	}

	task.attempts++
	if task.attempts >= as.asyncRetryMaxAttempts {
		_ = as.sideStore.MoveToDeadLetter(task, sendErr.Error())
		_ = as.sideStore.Delete(task.id)
		return
	}

	if err := as.sideStore.Save(task); err != nil {
		as.logger.Error("Failed to save retry side task", "error", err)
	}
	time.AfterFunc(as.asyncRetryBackoff, func() {
		_ = as.enqueueSide(task)
	})
}
