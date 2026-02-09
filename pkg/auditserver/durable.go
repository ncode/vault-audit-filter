package auditserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type sideTaskStore interface {
	Save(task sideTask) error
	Delete(id string) error
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
	ID         string `json:"id"`
	GroupName  string `json:"group_name"`
	Attempts   int    `json:"attempts"`
	Payload    []byte `json:"payload"`
	PayloadStr string `json:"payload_str"`
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
	if task.id == "" {
		return fmt.Errorf("empty task id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := persistedSideTask{
		ID:         task.id,
		GroupName:  task.groupName,
		Attempts:   task.attempts,
		Payload:    task.payload,
		PayloadStr: task.payloadStr,
	}
	b, err := marshalPersistedSideTask(p)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.pendingDir, task.id+".json"), b, 0o600)
}

func (s *fileSideTaskStore) Delete(id string) error {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	d := deadLetterTask{
		Persisted: persistedSideTask{
			ID:         task.id,
			GroupName:  task.groupName,
			Attempts:   task.attempts,
			Payload:    task.payload,
			PayloadStr: task.payloadStr,
		},
		Reason: reason,
	}
	b, err := marshalDeadLetterTask(d)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.deadDir, task.id+".json"), b, 0o600)
}

func (s *fileSideTaskStore) Pending() ([]sideTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.pendingDir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	tasks := make([]sideTask, 0, len(names))
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(s.pendingDir, name))
		if err != nil {
			return nil, err
		}
		var p persistedSideTask
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, err
		}
		tasks = append(tasks, sideTask{
			id:         p.ID,
			groupName:  p.GroupName,
			attempts:   p.Attempts,
			payload:    p.Payload,
			payloadStr: p.PayloadStr,
		})
	}
	return tasks, nil
}

func (as *AuditServer) replayDurablePending() {
	if as.sideStore == nil {
		return
	}
	tasks, err := as.sideStore.Pending()
	if err != nil {
		as.logger.Error("Failed to load durable pending tasks", "error", err)
		return
	}
	for _, task := range tasks {
		_ = as.enqueueSide(task)
	}
}
