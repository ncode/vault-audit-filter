package auditserver

import (
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ncode/vault-audit-filter/pkg/forwarder"
	"github.com/ncode/vault-audit-filter/pkg/messaging"
)

var defaultSideWorkers = 2

type sideTask struct {
	id          string
	groupName   string
	attempts    int
	maxAttempts int
	lastError   string
	cleanupOnly bool
	payload     []byte
	payloadStr  string
	messenger   messaging.Messenger
	forwarder   forwarder.Forwarder
}

type sideEffectProcessorConfig struct {
	logger           *slog.Logger
	queueSize        int
	enqueueMode      string
	enqueueTimeout   time.Duration
	durableEnabled   bool
	retryMaxAttempts int
	retryBackoff     time.Duration
	store            sideTaskStore
	adapterResolver  sideTaskAdapterResolver
}

type sideTaskAdapters struct {
	messenger messaging.Messenger
	forwarder forwarder.Forwarder
}

type sideTaskAdapterResolver func(groupName string) sideTaskAdapters

type sideEffectProcessor struct {
	logger           *slog.Logger
	queue            chan sideTask
	drops            atomic.Uint64
	taskSeq          atomic.Uint64
	enqueueMode      string
	enqueueTimeout   time.Duration
	durableEnabled   bool
	retryMaxAttempts int
	retryBackoff     time.Duration
	store            sideTaskStore
	adapterResolver  sideTaskAdapterResolver
}

func newSideEffectProcessor(config sideEffectProcessorConfig) *sideEffectProcessor {
	if config.retryMaxAttempts <= 0 {
		config.retryMaxAttempts = defaultRetryMaxAttempts
	}
	if config.retryBackoff <= 0 {
		config.retryBackoff = defaultRetryBackoff
	}
	queueSize := config.queueSize
	if queueSize <= 0 {
		queueSize = defaultAsyncQueueSize
	}
	processor := &sideEffectProcessor{
		logger:           config.logger,
		queue:            make(chan sideTask, queueSize),
		enqueueMode:      config.enqueueMode,
		enqueueTimeout:   config.enqueueTimeout,
		durableEnabled:   config.durableEnabled,
		retryMaxAttempts: config.retryMaxAttempts,
		retryBackoff:     config.retryBackoff,
		store:            config.store,
		adapterResolver:  config.adapterResolver,
	}
	return processor
}

func (p *sideEffectProcessor) Submit(req sideEffectRequest) bool {
	return p.enqueue(sideTask{
		groupName:  req.groupName,
		payload:    req.payload,
		payloadStr: req.payloadStr,
		messenger:  req.messenger,
		forwarder:  req.forwarder,
	})
}

func (p *sideEffectProcessor) enqueue(task sideTask) bool {
	if p.durableEnabled && p.store != nil {
		if task.id == "" {
			task.id = p.nextTaskID()
		}
		if task.maxAttempts == 0 {
			task.maxAttempts = p.retryMaxAttempts
		}
		if !task.cleanupOnly {
			if err := p.store.Save(task); err != nil {
				p.storageFailure("accept", err)
				return false
			}
		}
	}
	return p.queueTask(task)
}

// Internal queue retries never rewrite a task or reserve a delivery attempt.
func (p *sideEffectProcessor) queueTask(task sideTask) bool {
	if p.enqueueMode == "wait" {
		timeout := p.enqueueTimeout
		if timeout <= 0 {
			timeout = 5 * time.Millisecond
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case p.queue <- task:
			return true
		case <-timer.C:
			if p.durableEnabled {
				p.retry(task)
				return true
			}
			p.addDrop()
			return false
		}
	}

	select {
	case p.queue <- task:
		return true
	default:
		if p.durableEnabled {
			p.retry(task)
			return true
		}
		p.addDrop()
		return false
	}
}

func (p *sideEffectProcessor) nextTaskID() string {
	n := p.taskSeq.Add(1)
	return time.Now().Format("20060102150405.000000000") + "-" + strconv.FormatUint(n, 10)
}

func (p *sideEffectProcessor) startWorkers(n int) {
	if n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		go func() {
			for task := range p.queue {
				p.process(task)
			}
		}()
	}
}

func (p *sideEffectProcessor) process(task sideTask) {
	durable := p.durableEnabled && p.store != nil && task.id != ""
	if durable {
		if task.cleanupOnly {
			p.cleanup(task)
			return
		}
		if task.maxAttempts == 0 {
			task.maxAttempts = p.retryMaxAttempts
		}
		if task.attempts >= task.maxAttempts {
			p.deadLetter(task)
			return
		}
		reserved := task
		reserved.attempts++
		reserved.lastError = ""
		if err := p.store.Save(reserved); err != nil {
			p.storageFailure("reserve", err)
			p.retry(task)
			return
		}
		task = reserved
	}

	messenger := task.messenger
	fwd := task.forwarder
	if task.groupName != "" && p.adapterResolver != nil {
		adapters := p.adapterResolver(task.groupName)
		if messenger == nil {
			messenger = adapters.messenger
		}
		if fwd == nil {
			fwd = adapters.forwarder
		}
	}

	var sendErr error
	if messenger != nil {
		if err := messenger.Send(task.payloadStr); err != nil {
			if p.logger != nil {
				p.logger.Error("Failed to send notification", "error", err)
			}
			sendErr = err
		}
	}
	if fwd != nil {
		if err := fwd.Forward(task.payload); err != nil {
			if p.logger != nil {
				p.logger.Error("Failed to forward message", "error", err)
			}
			if sendErr == nil {
				sendErr = err
			}
		}
	}

	if !durable {
		return
	}

	if sendErr == nil {
		task.cleanupOnly = true
		p.cleanup(task)
		return
	}

	task.lastError = sendErr.Error()
	if task.attempts >= task.maxAttempts {
		p.deadLetter(task)
		return
	}
	p.retry(task)
}

// Persist the final outcome before archival so recovery retains a known
// failure. The reserved count already prevents redelivery if this write fails.
func (p *sideEffectProcessor) deadLetter(task sideTask) {
	if task.lastError == "" {
		task.lastError = "final attempt interrupted; outcome unknown"
	}
	if err := p.store.Save(task); err != nil {
		p.storageFailure("record outcome", err)
		p.retry(task)
		return
	}
	if err := p.store.MoveToDeadLetter(task, task.lastError); err != nil {
		p.storageFailure("archive", err)
		p.retry(task)
	}
}

func (p *sideEffectProcessor) cleanup(task sideTask) {
	if err := p.store.Delete(task.id); err != nil {
		p.storageFailure("cleanup", err)
		p.retry(task)
	}
}

func (p *sideEffectProcessor) retry(task sideTask) {
	time.AfterFunc(p.retryBackoff, func() {
		p.queueTask(task)
	})
}

func (p *sideEffectProcessor) storageFailure(operation string, err error) {
	if p.logger != nil {
		// Store errors may embed paths, payloads or credentials. Log the error
		// type and operation, keeping the sensitive error text in the adapter.
		p.logger.Error("Durable side task storage failed", "operation", operation, "error_type", fmt.Sprintf("%T", err))
	}
}

func (p *sideEffectProcessor) Drops() uint64 {
	return p.drops.Load()
}

func (p *sideEffectProcessor) addDrop() {
	p.drops.Add(1)
}
