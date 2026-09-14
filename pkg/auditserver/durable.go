package auditserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type sideTaskStore interface {
	Save(task sideTask) error
	Delete(id string) error
	// MoveToDeadLetter publishes the archive before removing pending work.
	// Repeating a partial handoff preserves the existing archive and its reason.
	MoveToDeadLetter(task sideTask, reason string) error
	Pending() ([]sideTask, error)
}

type fileSideTaskStore struct {
	baseDir    string
	pendingDir string
	deadDir    string
	mu         sync.Mutex
}

type persistedSideTask struct {
	ID          string          `json:"id"`
	GroupName   string          `json:"group_name"`
	Attempts    int             `json:"attempts"`
	MaxAttempts json.RawMessage `json:"max_attempts,omitempty"`
	LastError   string          `json:"last_error,omitempty"`
	Payload     []byte          `json:"payload"`
	PayloadStr  string          `json:"payload_str"`
}

type deadLetterTask struct {
	Persisted persistedSideTask `json:"persisted"`
	Reason    string            `json:"reason"`
}

var marshalPersistedSideTask = func(p persistedSideTask) ([]byte, error) {
	return json.Marshal(p)
}

var marshalDeadLetterTask = func(d deadLetterTask) ([]byte, error) {
	return json.Marshal(d)
}

var createSideTaskTemp = os.CreateTemp

func newFileSideTaskStore(baseDir string) (*fileSideTaskStore, error) {
	pendingDir := filepath.Join(baseDir, "pending")
	deadDir := filepath.Join(baseDir, "deadletter")
	if err := os.MkdirAll(pendingDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(deadDir, 0o755); err != nil {
		return nil, err
	}
	return &fileSideTaskStore{baseDir: baseDir, pendingDir: pendingDir, deadDir: deadDir}, nil
}

func (s *fileSideTaskStore) Save(task sideTask) error {
	if err := validateSideTask(task); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := marshalPersistedSideTask(task.persisted())
	if err != nil {
		return err
	}
	return writeSideTaskFile(filepath.Join(s.pendingDir, task.id+".json"), b)
}

func (s *fileSideTaskStore) Delete(id string) error {
	if id == "" {
		return nil
	}
	if err := validateSideTask(sideTask{id: id}); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deletePending(id)
}

func (s *fileSideTaskStore) deletePending(id string) error {
	err := os.Remove(filepath.Join(s.pendingDir, id+".json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *fileSideTaskStore) MoveToDeadLetter(task sideTask, reason string) error {
	if task.id == "" {
		return nil
	}
	if err := validateSideTask(task); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exists, err := s.hasDeadLetter(task.id)
	if err != nil {
		return err
	}
	if !exists {
		b, err := marshalDeadLetterTask(deadLetterTask{Persisted: task.persisted(), Reason: reason})
		if err != nil {
			return err
		}
		if err := writeSideTaskFile(filepath.Join(s.deadDir, task.id+".json"), b); err != nil {
			return err
		}
	}
	return s.deletePending(task.id)
}

func (s *fileSideTaskStore) Pending() ([]sideTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.pendingDir)
	if err != nil {
		return nil, err
	}
	tasks := make([]sideTask, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".side-task-") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.pendingDir, e.Name()))
		if err != nil {
			return nil, err
		}
		var p persistedSideTask
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, err
		}
		task, err := p.task(e.Name())
		if err != nil {
			return nil, err
		}
		task.cleanupOnly, err = s.hasDeadLetter(task.id)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}

func validateSideTask(task sideTask) error {
	if task.id == "" || task.id == "." || task.id == ".." || strings.ContainsAny(task.id, `/\`) || strings.HasPrefix(task.id, ".side-task-") {
		return fmt.Errorf("invalid task id")
	}
	if task.attempts < 0 || task.maxAttempts < 0 {
		return fmt.Errorf("invalid delivery accounting")
	}
	return nil
}

func (task sideTask) persisted() persistedSideTask {
	p := persistedSideTask{
		ID: task.id, GroupName: task.groupName, Attempts: task.attempts,
		LastError: task.lastError, Payload: task.payload, PayloadStr: task.payloadStr,
	}
	if task.maxAttempts != 0 {
		p.MaxAttempts = json.RawMessage(strconv.Itoa(task.maxAttempts))
	}
	return p
}

func (p persistedSideTask) task(name string) (sideTask, error) {
	task := sideTask{
		id: p.ID, groupName: p.GroupName, attempts: p.Attempts,
		lastError: p.LastError, payload: p.Payload, payloadStr: p.PayloadStr,
	}
	if len(p.MaxAttempts) != 0 {
		if err := json.Unmarshal(p.MaxAttempts, &task.maxAttempts); err != nil || task.maxAttempts <= 0 {
			return sideTask{}, fmt.Errorf("invalid stored delivery limit")
		}
	}
	if err := validateSideTask(task); err != nil {
		return sideTask{}, err
	}
	if name != task.id+".json" {
		return sideTask{}, fmt.Errorf("task id does not match record filename")
	}
	return task, nil
}

func (s *fileSideTaskStore) hasDeadLetter(id string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(s.deadDir, id+".json"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var dead deadLetterTask
	if err := json.Unmarshal(b, &dead); err != nil {
		return false, err
	}
	_, err = dead.Persisted.task(id + ".json")
	return err == nil, err
}

// Publish only complete records. A crash before rename leaves the previous
// record intact; Pending ignores temporary files left by interrupted writes.
func writeSideTaskFile(path string, data []byte) error {
	f, err := createSideTaskTemp(filepath.Dir(path), ".side-task-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (p *sideEffectProcessor) replayDurablePending() {
	if p.store == nil {
		return
	}
	tasks, err := p.store.Pending()
	if err != nil {
		p.storageFailure("load pending", err)
		time.AfterFunc(p.retryBackoff, p.replayDurablePending)
		return
	}
	for _, task := range tasks {
		// This processor already owns newly accepted tasks, including ones in
		// flight while a startup load retries. Never enqueue their snapshots.
		if strings.HasPrefix(task.id, p.taskIDPrefix) {
			continue
		}
		if !p.enqueue(task) {
			p.retry(task)
		}
	}
}
