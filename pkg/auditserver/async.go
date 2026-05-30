package auditserver

import (
	"log/slog"
	"strconv"
	"sync/atomic"
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

type sideEffectProcessorConfig struct {
	logger               *slog.Logger
	queueSize            int
	enqueueMode          string
	enqueueTimeout       time.Duration
	durableEnabled       bool
	retryMaxAttempts     int
	retryBackoff         time.Duration
	store                sideTaskStore
	adapterResolver      sideTaskAdapterResolver
	mirrorDrops          *atomic.Uint64
	mirrorTaskSeq        *atomic.Uint64
	mirrorQueue          *chan sideTask
	mirrorEnqueueMode    *string
	mirrorEnqueueTimeout *time.Duration
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
	mirrorDrops      *atomic.Uint64
	mirrorTaskSeq    *atomic.Uint64
}

func newSideEffectProcessor(config sideEffectProcessorConfig) *sideEffectProcessor {
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
		mirrorDrops:      config.mirrorDrops,
		mirrorTaskSeq:    config.mirrorTaskSeq,
	}
	if config.mirrorQueue != nil {
		*config.mirrorQueue = processor.queue
	}
	if config.mirrorEnqueueMode != nil {
		*config.mirrorEnqueueMode = processor.enqueueMode
	}
	if config.mirrorEnqueueTimeout != nil {
		*config.mirrorEnqueueTimeout = processor.enqueueTimeout
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
		if err := p.store.Save(task); err != nil {
			if p.logger != nil {
				p.logger.Error("Failed to persist durable side task", "error", err)
			}
			return false
		}
	}

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
				time.AfterFunc(p.retryBackoff, func() {
					_ = p.enqueue(task)
				})
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
			time.AfterFunc(p.retryBackoff, func() {
				_ = p.enqueue(task)
			})
			return true
		}
		p.addDrop()
		return false
	}
}

func (p *sideEffectProcessor) nextTaskID() string {
	var n uint64
	if p.mirrorTaskSeq != nil {
		n = p.mirrorTaskSeq.Add(1)
	} else {
		n = p.taskSeq.Add(1)
	}
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

	if !p.durableEnabled || p.store == nil || task.id == "" {
		return
	}

	if sendErr == nil {
		_ = p.store.Delete(task.id)
		return
	}

	task.attempts++
	if task.attempts >= p.retryMaxAttempts {
		_ = p.store.MoveToDeadLetter(task, sendErr.Error())
		_ = p.store.Delete(task.id)
		return
	}

	if err := p.store.Save(task); err != nil && p.logger != nil {
		p.logger.Error("Failed to save retry side task", "error", err)
	}
	time.AfterFunc(p.retryBackoff, func() {
		_ = p.enqueue(task)
	})
}

func (p *sideEffectProcessor) Drops() uint64 {
	if p.mirrorDrops != nil {
		return p.mirrorDrops.Load()
	}
	return p.drops.Load()
}

func (p *sideEffectProcessor) addDrop() {
	if p.mirrorDrops != nil {
		p.mirrorDrops.Add(1)
		return
	}
	p.drops.Add(1)
}
