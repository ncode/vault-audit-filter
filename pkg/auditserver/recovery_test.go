package auditserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSideEffectProcessor_DeadLetterFailureRetainsPending(t *testing.T) {
	task := sideTask{id: "task", messenger: &dummyMessenger{sendErr: errors.New("delivery failed")}}
	store := &errSideTaskStore{deadErr: errors.New("archive failed"), pending: []sideTask{task}}
	processor := newSideEffectProcessor(sideEffectProcessorConfig{
		durableEnabled: true, retryMaxAttempts: 1, retryBackoff: time.Hour, store: store,
	})
	processor.process(task)
	pending, err := store.Pending()
	require.NoError(t, err)
	assert.NotEmpty(t, pending, "a failed archive must retain recoverable work")
	assert.Zero(t, store.deleteCalls, "failed archival must not delete pending work")
}

func writePendingRecord(t *testing.T, store *fileSideTaskStore, record string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(store.pendingDir, "task.json"), []byte(record), 0o600))
}

func TestFileSideTaskStore_RecoveryAccounting(t *testing.T) {
	t.Run("round trip fixed limit and outcome", func(t *testing.T) {
		store, err := newFileSideTaskStore(t.TempDir())
		require.NoError(t, err)
		writePendingRecord(t, store, `{"id":"task","attempts":3,"max_attempts":3,"last_error":"delivery failed"}`)
		tasks, err := store.Pending()
		require.NoError(t, err)
		require.Len(t, tasks, 1)
		require.NoError(t, store.Save(tasks[0]))
		data, err := os.ReadFile(filepath.Join(store.pendingDir, "task.json"))
		require.NoError(t, err)
		var record map[string]any
		require.NoError(t, json.Unmarshal(data, &record))
		assert.Equal(t, float64(3), record["attempts"])
		assert.Equal(t, float64(3), record["max_attempts"])
		assert.Equal(t, "delivery failed", record["last_error"])
	})
	for _, record := range []string{
		`{"id":"task","attempts":-1}`,
		`{"id":"task","max_attempts":0}`,
		`{"id":"task","max_attempts":-1}`,
		`{"id":"task","max_attempts":null}`,
		`{"id":"task","max_attempts":"three"}`,
		`{"id":"../escape"}`,
		`{"id":"different"}`,
	} {
		t.Run(record, func(t *testing.T) {
			store, err := newFileSideTaskStore(t.TempDir())
			require.NoError(t, err)
			writePendingRecord(t, store, record)
			_, err = store.Pending()
			require.Error(t, err)
			data, err := os.ReadFile(filepath.Join(store.pendingDir, "task.json"))
			require.NoError(t, err)
			assert.Equal(t, record, string(data))
		})
	}
}

func TestFileSideTaskStore_AtomicRecordReplacement(t *testing.T) {
	store, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)
	task := sideTask{id: "task", payloadStr: "original"}
	require.NoError(t, store.Save(task))
	path := filepath.Join(store.pendingDir, "task.json")
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	snapshot := filepath.Join(t.TempDir(), "snapshot.json")
	require.NoError(t, os.Link(path, snapshot))
	task.payloadStr = "updated"
	require.NoError(t, store.Save(task))
	saved, err := os.ReadFile(snapshot)
	require.NoError(t, err)
	assert.Equal(t, original, saved, "publishing an update must replace, not overwrite, the old record")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	require.NoError(t, os.WriteFile(filepath.Join(store.pendingDir, ".side-task-interrupted"), []byte("{"), 0o600))
	tasks, err := store.Pending()
	require.NoError(t, err)
	require.Len(t, tasks, 1)
	assert.Equal(t, "updated", tasks[0].payloadStr)
}

func TestFileSideTaskStore_CompleteDeadLetterHandoff(t *testing.T) {
	store, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)
	task := sideTask{id: "task", payloadStr: "payload"}
	require.NoError(t, store.Save(task))
	require.NoError(t, store.MoveToDeadLetter(task, "known failure"))
	pending, err := store.Pending()
	require.NoError(t, err)
	assert.Empty(t, pending)

	// Simulate an interruption after publication but before pending removal.
	require.NoError(t, store.Save(task))
	pending, err = store.Pending()
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.True(t, pending[0].cleanupOnly, "even legacy overlaps must never deliver")
	require.NoError(t, store.MoveToDeadLetter(task, "unknown outcome"))
	data, err := os.ReadFile(filepath.Join(store.deadDir, "task.json"))
	require.NoError(t, err)
	var dead deadLetterTask
	require.NoError(t, json.Unmarshal(data, &dead))
	assert.Equal(t, "known failure", dead.Reason)
	pending, err = store.Pending()
	require.NoError(t, err)
	assert.Empty(t, pending)
}

func TestFileSideTaskStore_FailedPublication(t *testing.T) {
	store, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)
	task := sideTask{id: "task", attempts: 1, maxAttempts: 3}
	require.NoError(t, store.Save(task))
	original, err := os.ReadFile(filepath.Join(store.pendingDir, "task.json"))
	require.NoError(t, err)
	// A filesystem failure before publication must leave the prior reservation.
	pendingDir := store.pendingDir
	store.pendingDir = filepath.Join(pendingDir, "unavailable")
	task.attempts++
	err = store.Save(task)
	store.pendingDir = pendingDir
	require.Error(t, err)
	data, err := os.ReadFile(filepath.Join(store.pendingDir, "task.json"))
	require.NoError(t, err)
	assert.Equal(t, original, data)

	require.NoError(t, os.Remove(store.deadDir))
	require.Error(t, store.MoveToDeadLetter(task, "failure"))
	data, err = os.ReadFile(filepath.Join(store.pendingDir, "task.json"))
	require.NoError(t, err)
	assert.Equal(t, original, data)
}

func TestFileSideTaskStore_UnpublishedUpdateRetainsRecord(t *testing.T) {
	for _, failure := range []string{"write", "write and close", "rename"} {
		t.Run(failure, func(t *testing.T) {
			store, err := newFileSideTaskStore(t.TempDir())
			require.NoError(t, err)
			task := sideTask{id: "task", attempts: 1, maxAttempts: 3}
			require.NoError(t, store.Save(task))
			original, err := os.ReadFile(filepath.Join(store.pendingDir, "task.json"))
			require.NoError(t, err)
			create := createSideTaskTemp
			t.Cleanup(func() {
				createSideTaskTemp = create
			})
			createSideTaskTemp = func(dir, pattern string) (*os.File, error) {
				f, err := create(dir, pattern)
				require.NoError(t, err)
				if failure == "rename" {
					// The open file remains writable, but publication from its
					// original name will fail independently of user permissions.
					require.NoError(t, os.Rename(f.Name(), f.Name()+".unpublished"))
					return f, nil
				}
				require.NoError(t, f.Close())
				if failure == "write" {
					return os.Open(f.Name())
				}
				return f, nil
			}
			task.attempts++
			err = store.Save(task)
			require.Error(t, err)
			if failure == "write and close" {
				assert.Contains(t, err.Error(), "write")
				assert.Contains(t, err.Error(), "close", "closing errors must also be retained")
			}
			data, err := os.ReadFile(filepath.Join(store.pendingDir, "task.json"))
			require.NoError(t, err)
			assert.Equal(t, original, data)
			pending, err := store.Pending()
			require.NoError(t, err)
			require.Len(t, pending, 1)
			assert.Equal(t, 1, pending[0].attempts)
		})
	}
}

func TestFileSideTaskStore_InvalidHandoffRetainsPending(t *testing.T) {
	for _, record := range []string{"{", `{"persisted":{"id":"other"}}`, `{"persisted":{"id":"task","max_attempts":0}}`, "unreadable"} {
		t.Run(record, func(t *testing.T) {
			store, err := newFileSideTaskStore(t.TempDir())
			require.NoError(t, err)
			task := sideTask{id: "task"}
			require.NoError(t, store.Save(task))
			archive := filepath.Join(store.deadDir, "task.json")
			if record == "unreadable" {
				require.NoError(t, os.Mkdir(archive, 0o700))
			} else {
				require.NoError(t, os.WriteFile(archive, []byte(record), 0o600))
			}
			require.Error(t, store.MoveToDeadLetter(task, "replacement"))
			_, err = store.Pending()
			require.Error(t, err)
			_, err = os.Stat(filepath.Join(store.pendingDir, "task.json"))
			require.NoError(t, err)
			if record != "unreadable" {
				data, err := os.ReadFile(archive)
				require.NoError(t, err)
				assert.Equal(t, record, string(data))
			}
		})
	}
	store, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)
	for _, id := range []string{".", "..", "../escape", `dir\task`, ".side-task-reserved"} {
		assert.Error(t, store.Save(sideTask{id: id}))
		assert.Error(t, store.MoveToDeadLetter(sideTask{id: id}, "invalid"))
		assert.Error(t, store.Delete(id))
	}
}

// Faults wrap the real file adapter, so retries are checked against published
// records. Tests drive processing synchronously and virtual time drives retries.
type recoveryFaultStore struct {
	sideTaskStore
	saveErr, deadErr, deleteErr error
	saves                       []sideTask
	deadCalls, deleteCalls      int
}

func (s *recoveryFaultStore) Save(task sideTask) error {
	s.saves = append(s.saves, task)
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.sideTaskStore.Save(task)
}

func (s *recoveryFaultStore) MoveToDeadLetter(task sideTask, reason string) error {
	s.deadCalls++
	if s.deadErr != nil {
		return s.deadErr
	}
	return s.sideTaskStore.MoveToDeadLetter(task, reason)
}

func (s *recoveryFaultStore) Delete(id string) error {
	s.deleteCalls++
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.sideTaskStore.Delete(id)
}

type checkedDelivery func()

func (f checkedDelivery) Send(string) error    { f(); return nil }
func (f checkedDelivery) Forward([]byte) error { f(); return nil }

func processRecoveryRetry(t *testing.T, p *sideEffectProcessor) {
	t.Helper()
	time.Sleep(p.retryBackoff)
	synctest.Wait()
	select {
	case task := <-p.queue:
		p.process(task)
	default:
		t.Fatal("storage or delivery retry was not scheduled")
	}
}

func TestSideEffectProcessor_ReservationBeforeDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		files, err := newFileSideTaskStore(t.TempDir())
		require.NoError(t, err)
		store := &recoveryFaultStore{sideTaskStore: files}
		calls := 0
		delivery := checkedDelivery(func() {
			pending, err := files.Pending()
			require.NoError(t, err)
			require.Len(t, pending, 1)
			assert.Equal(t, 2, pending[0].attempts)
			assert.Equal(t, 3, pending[0].maxAttempts)
			assert.Empty(t, pending[0].lastError, "a reservation clears the preceding outcome")
			calls++
		})
		task := sideTask{id: "task", attempts: 1, maxAttempts: 3, lastError: "previous failure", messenger: delivery, forwarder: delivery}
		require.NoError(t, files.Save(task))
		p := newSideEffectProcessor(sideEffectProcessorConfig{durableEnabled: true, retryMaxAttempts: 5, retryBackoff: time.Second, store: store})
		store.saveErr = errors.New("reservation unavailable")
		p.process(task)
		assert.Zero(t, calls)
		processRecoveryRetry(t, p)
		assert.Zero(t, calls)
		store.saveErr = nil
		processRecoveryRetry(t, p)
		assert.Equal(t, 2, calls, "both destinations share one reserved attempt")
		for _, saved := range store.saves {
			assert.Equal(t, 2, saved.attempts, "failed writes must retry the same reservation")
		}
		pending, err := files.Pending()
		require.NoError(t, err)
		assert.Empty(t, pending)
	})
}

func TestSideEffectProcessor_FixedLimitRecovery(t *testing.T) {
	for _, record := range []string{
		`{"id":"task","group_name":"group","attempts":2}`,
		`{"id":"task","group_name":"group","attempts":2,"max_attempts":3}`,
	} {
		t.Run(record, func(t *testing.T) {
			files, err := newFileSideTaskStore(t.TempDir())
			require.NoError(t, err)
			writePendingRecord(t, files, record)
			p := newSideEffectProcessor(sideEffectProcessorConfig{durableEnabled: true, retryMaxAttempts: 3, store: files})
			p.replayDurablePending() // No workers: migration may persist, delivery must wait.
			pending, err := files.Pending()
			require.NoError(t, err)
			require.Len(t, pending, 1)
			assert.Equal(t, 2, pending[0].attempts)
			assert.Equal(t, 3, pending[0].maxAttempts)

			// Reopen the store and processor under a different runtime limit.
			files, err = newFileSideTaskStore(files.baseDir)
			require.NoError(t, err)
			msg := &dummyMessenger{sendErr: errors.New("final failure")}
			fwd := &dummyForwarder{}
			p = newSideEffectProcessor(sideEffectProcessorConfig{durableEnabled: true, retryMaxAttempts: 5, store: files,
				adapterResolver: func(string) sideTaskAdapters { return sideTaskAdapters{messenger: msg, forwarder: fwd} },
			})
			p.replayDurablePending()
			p.process(<-p.queue)
			assert.Equal(t, 1, msg.Calls())
			assert.Equal(t, 1, fwd.Calls())
			data, err := os.ReadFile(filepath.Join(files.deadDir, "task.json"))
			require.NoError(t, err)
			assert.Contains(t, string(data), "final failure")
			require.True(t, p.Submit(sideEffectRequest{}))
			pending, err = files.Pending()
			require.NoError(t, err)
			require.Len(t, pending, 1)
			assert.Equal(t, 5, pending[0].maxAttempts, "new tasks use the current limit")
		})
	}
}

func TestSideEffectProcessor_InterruptedFinalReservation(t *testing.T) {
	files, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)
	task := sideTask{id: "task", groupName: "group", attempts: 2, maxAttempts: 3, lastError: "previous failure"}
	require.NoError(t, files.Save(task))
	p := newSideEffectProcessor(sideEffectProcessorConfig{durableEnabled: true, retryMaxAttempts: 3, store: files})
	task.messenger = checkedDelivery(func() { panic("interrupted before sending") })
	require.Panics(t, func() { p.process(task) })
	files, err = newFileSideTaskStore(files.baseDir)
	require.NoError(t, err)
	msg, fwd := &dummyMessenger{}, &dummyForwarder{}
	p = newSideEffectProcessor(sideEffectProcessorConfig{durableEnabled: true, retryMaxAttempts: 5, store: files,
		adapterResolver: func(string) sideTaskAdapters { return sideTaskAdapters{messenger: msg, forwarder: fwd} },
	})
	p.replayDurablePending()
	p.process(<-p.queue)
	assert.Zero(t, msg.Calls())
	assert.Zero(t, fwd.Calls())
	data, err := os.ReadFile(filepath.Join(files.deadDir, "task.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "unknown")
	assert.NotContains(t, string(data), "previous failure")
}

func TestSideEffectProcessor_LegacyMigrationRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		files, err := newFileSideTaskStore(t.TempDir())
		require.NoError(t, err)
		writePendingRecord(t, files, `{"id":"task","group_name":"group","attempts":2}`)
		store := &recoveryFaultStore{sideTaskStore: files, saveErr: errors.New("storage unavailable")}
		msg := &dummyMessenger{}
		p := newSideEffectProcessor(sideEffectProcessorConfig{durableEnabled: true, retryMaxAttempts: 3, retryBackoff: time.Second, store: store,
			adapterResolver: func(string) sideTaskAdapters { return sideTaskAdapters{messenger: msg} },
		})
		p.replayDurablePending()
		assert.Empty(t, p.queue)
		processRecoveryRetry(t, p)
		assert.Zero(t, msg.Calls())
		pending, err := files.Pending()
		require.NoError(t, err)
		require.Len(t, pending, 1)
		assert.Equal(t, 2, pending[0].attempts)
		assert.Zero(t, pending[0].maxAttempts)
		store.saveErr = nil
		processRecoveryRetry(t, p)
		assert.Equal(t, 1, msg.Calls())
		assert.Equal(t, 3, store.saves[len(store.saves)-1].attempts)
		assert.Equal(t, 3, store.saves[len(store.saves)-1].maxAttempts)
	})
}

func TestSideEffectProcessor_AcceptedLimitSurvivesQueueRetry(t *testing.T) {
	for _, mode := range []string{"drop", "wait"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				files, err := newFileSideTaskStore(t.TempDir())
				require.NoError(t, err)
				store := &recoveryFaultStore{sideTaskStore: files}
				p := newSideEffectProcessor(sideEffectProcessorConfig{durableEnabled: true, retryMaxAttempts: 3, retryBackoff: time.Second,
					queueSize: 1, enqueueMode: mode, enqueueTimeout: time.Millisecond, store: store})
				p.queue <- sideTask{}
				require.True(t, p.Submit(sideEffectRequest{}))
				pending, err := files.Pending()
				require.NoError(t, err)
				require.Len(t, pending, 1)
				assert.Equal(t, 3, pending[0].maxAttempts)
				assert.Zero(t, pending[0].attempts)
				p.retryMaxAttempts = 5
				<-p.queue
				// Storage is unavailable during the queue retry: the accepted record
				// must not be rewritten, lost or charged an attempt just to queue it.
				store.saveErr = errors.New("storage unavailable")
				time.Sleep(p.retryBackoff)
				synctest.Wait()
				require.Len(t, p.queue, 1)
				task := <-p.queue
				assert.Equal(t, 3, task.maxAttempts)
				assert.Zero(t, task.attempts)
				assert.Len(t, store.saves, 1)
				assert.Zero(t, p.Drops())
			})
		})
	}
}

func TestSideEffectProcessor_RecoveredTerminalOutcome(t *testing.T) {
	for _, record := range []string{
		`{"id":"task","group_name":"group","attempts":3,"max_attempts":3,"last_error":"known failure"}`,
		`{"id":"task","group_name":"group","attempts":4,"max_attempts":3,"last_error":"known failure"}`,
		`{"id":"task","group_name":"group","attempts":4,"last_error":"known failure"}`,
	} {
		t.Run(record, func(t *testing.T) {
			files, err := newFileSideTaskStore(t.TempDir())
			require.NoError(t, err)
			writePendingRecord(t, files, record)
			msg, fwd := &dummyMessenger{}, &dummyForwarder{}
			p := newSideEffectProcessor(sideEffectProcessorConfig{durableEnabled: true, retryMaxAttempts: 3, store: files,
				adapterResolver: func(string) sideTaskAdapters { return sideTaskAdapters{messenger: msg, forwarder: fwd} },
			})
			p.startWorkers(0)
			p.replayDurablePending()
			_, err = os.Stat(filepath.Join(files.deadDir, "task.json"))
			require.ErrorIs(t, err, os.ErrNotExist, "zero workers must not archive recovered tasks")
			p.process(<-p.queue)
			assert.Zero(t, msg.Calls())
			assert.Zero(t, fwd.Calls())
			data, err := os.ReadFile(filepath.Join(files.deadDir, "task.json"))
			require.NoError(t, err)
			assert.Contains(t, string(data), "known failure")
		})
	}
}

func TestSideEffectProcessor_PartialSuccessSharesAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		files, err := newFileSideTaskStore(t.TempDir())
		require.NoError(t, err)
		msg, fwd := &dummyMessenger{}, &dummyForwarder{forwardErr: errors.New("forward failed")}
		p := newSideEffectProcessor(sideEffectProcessorConfig{durableEnabled: true, retryMaxAttempts: 2, retryBackoff: time.Second, store: files})
		require.True(t, p.Submit(sideEffectRequest{messenger: msg, forwarder: fwd}))
		p.process(<-p.queue)
		pending, err := files.Pending()
		require.NoError(t, err)
		require.Len(t, pending, 1)
		assert.Equal(t, 1, pending[0].attempts)
		processRecoveryRetry(t, p)
		assert.Equal(t, 2, msg.Calls())
		assert.Equal(t, 2, fwd.Calls())
		data, err := os.ReadFile(filepath.Join(files.deadDir, pending[0].id+".json"))
		require.NoError(t, err)
		var dead deadLetterTask
		require.NoError(t, json.Unmarshal(data, &dead))
		assert.Equal(t, 2, dead.Persisted.Attempts)
		assert.Equal(t, "forward failed", dead.Reason)
	})
}

func TestSideEffectProcessor_StorageOnlyRetries(t *testing.T) {
	for _, operation := range []string{"archive", "successful cleanup", "overlap cleanup", "terminal outcome"} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				files, err := newFileSideTaskStore(t.TempDir())
				require.NoError(t, err)
				store := &recoveryFaultStore{sideTaskStore: files}
				msg, fwd := &dummyMessenger{}, &dummyForwarder{}
				task := sideTask{id: "task", groupName: "group", maxAttempts: 1, messenger: msg, forwarder: fwd}
				require.NoError(t, files.Save(task))
				var logs bytes.Buffer
				p := newSideEffectProcessor(sideEffectProcessorConfig{durableEnabled: true, retryMaxAttempts: 3, retryBackoff: time.Second, store: store,
					logger: slog.New(slog.NewTextHandler(&logs, nil)),
				})
				failure := errors.New("private-payload credential-value")
				switch operation {
				case "archive":
					msg.sendErr = errors.New("final failure")
					store.deadErr = failure
				case "successful cleanup":
					store.deleteErr = failure
				case "overlap cleanup":
					require.NoError(t, files.MoveToDeadLetter(task, "original reason"))
					require.NoError(t, files.Save(sideTask{id: "task", groupName: "group"}))
					store.deleteErr = failure
					p.replayDurablePending()
					task = <-p.queue
					task.messenger, task.forwarder = msg, fwd
				case "terminal outcome":
					task.attempts, task.lastError = 1, "known failure"
					require.NoError(t, files.Save(task))
					store.saveErr = failure
				}
				p.process(task)
				calls := msg.Calls()
				for range 2 {
					processRecoveryRetry(t, p)
				}
				assert.Equal(t, calls, msg.Calls())
				assert.Equal(t, calls, fwd.Calls())
				pending, err := files.Pending()
				require.NoError(t, err)
				require.Len(t, pending, 1)
				for _, saved := range store.saves {
					assert.LessOrEqual(t, saved.attempts, 1)
				}
				assert.Zero(t, p.Drops())
				assert.NotEmpty(t, logs.String(), "storage failure must be observable")
				assert.NotContains(t, logs.String(), "private-payload")
				assert.NotContains(t, logs.String(), "credential-value")
				store.saveErr, store.deadErr, store.deleteErr = nil, nil, nil
				processRecoveryRetry(t, p)
				pending, err = files.Pending()
				require.NoError(t, err)
				assert.Empty(t, pending)
				assert.Equal(t, calls, msg.Calls())
				assert.Equal(t, calls, fwd.Calls())
				if operation == "overlap cleanup" {
					data, err := os.ReadFile(filepath.Join(files.deadDir, "task.json"))
					require.NoError(t, err)
					assert.Contains(t, string(data), "original reason")
				}
			})
		})
	}
}

func TestFileSideTaskStore_FailedHandoffCleanup(t *testing.T) {
	store, err := newFileSideTaskStore(t.TempDir())
	require.NoError(t, err)
	path := filepath.Join(store.pendingDir, "task.json")
	require.NoError(t, os.Mkdir(path, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(path, "blocker"), nil, 0o600))
	require.Error(t, store.MoveToDeadLetter(sideTask{id: "task"}, "known failure"))
	data, err := os.ReadFile(filepath.Join(store.deadDir, "task.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "known failure")
}

func TestReplayDurablePending_RetriesLoadWithoutDuplicatingLiveTasks(t *testing.T) {
	for _, name := range []string{"recovered only", "with queued live task", "with retrying live task"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				files, err := newFileSideTaskStore(t.TempDir())
				require.NoError(t, err)
				previous := newSideEffectProcessor(sideEffectProcessorConfig{})
				recoveredID := previous.nextTaskID()
				require.NoError(t, files.Save(sideTask{id: recoveredID, attempts: 1, maxAttempts: 3}))
				// An unreadable dead letter prevents the initial pending snapshot.
				blocked := filepath.Join(files.deadDir, recoveredID+".json")
				require.NoError(t, os.Mkdir(blocked, 0o700))
				var logs bytes.Buffer
				p := newSideEffectProcessor(sideEffectProcessorConfig{
					durableEnabled: true, retryBackoff: time.Second, store: files,
					logger: slog.New(slog.NewTextHandler(&logs, nil)),
				})
				p.replayDurablePending()
				time.Sleep(p.retryBackoff)
				synctest.Wait()
				assert.Empty(t, p.queue, "failed loads must not permit delivery")
				want := 1
				msg := &dummyMessenger{}
				liveAttempts := 0
				if name != "recovered only" {
					require.True(t, p.Submit(sideEffectRequest{messenger: msg}))
					want++
				}
				if name == "with retrying live task" {
					msg.sendErr = errors.New("delivery failed")
					p.process(<-p.queue)
					liveAttempts = 1
					msg.sendErr = nil
				}
				require.NoError(t, os.Remove(blocked))
				time.Sleep(p.retryBackoff)
				synctest.Wait()
				require.Len(t, p.queue, want, "resume recovery without requeuing live work")
				assert.Equal(t, 2, bytes.Count(logs.Bytes(), []byte("load pending")))
				for range want {
					task := <-p.queue
					if task.id == recoveredID {
						assert.Equal(t, 1, task.attempts, "load retries do not reserve attempts")
					} else {
						assert.Equal(t, liveAttempts, task.attempts)
					}
					p.process(task)
				}
				time.Sleep(2 * p.retryBackoff)
				synctest.Wait()
				assert.Empty(t, p.queue, "successful recovery must stop retrying the load")
				pending, err := files.Pending()
				require.NoError(t, err)
				assert.Empty(t, pending)
				assert.Zero(t, p.Drops())
				assert.Equal(t, want-1+liveAttempts, msg.Calls())
			})
		})
	}
}
