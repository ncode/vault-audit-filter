package forwarder

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUDPForwarder(t *testing.T) {
	// Start a mock UDP server
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	assert.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	assert.NoError(t, err)
	defer conn.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			_, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
		}
	}()

	// Create a new UDPForwarder
	forwarder, err := NewUDPForwarder(conn.LocalAddr().String())
	assert.NoError(t, err)

	// Test Forward method
	testData := []byte("test message")
	err = forwarder.Forward(testData)
	assert.NoError(t, err)
}

func TestUDPForwarder_InvalidAddress(t *testing.T) {
	// Try to create a UDPForwarder with an invalid address
	_, err := NewUDPForwarder("invalid-address")
	assert.Error(t, err)
}

func TestUDPForwarder_UnreachableAddress(t *testing.T) {
	// Try to create a UDPForwarder with an unreachable address
	forwarder, err := NewUDPForwarder("8.8.8.8:12345")
	assert.NoError(t, err) // Creating the forwarder should succeed

	// Trying to forward should not return an error for UDP
	err = forwarder.Forward([]byte("test message"))
	assert.NoError(t, err)
}

func TestForwarderInterface(t *testing.T) {
	// This test ensures that UDPForwarder implements the Forwarder interface
	var _ Forwarder = (*UDPForwarder)(nil)
}

func TestNewUDPForwarder_Failure(t *testing.T) {
	// Attempt to create a new UDPForwarder with an invalid address
	_, err := NewUDPForwarder("256.0.0.1:12345") // Invalid IP address

	// Check that the error is not nil
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no such host")

	// Attempt to create a new UDPForwarder with a valid but unreachable address
	_, err = NewUDPForwarder("203.0.113.1:12345") // TEST-NET-3 address, should be unreachable

	// This should not return an error for UDP, as it's connectionless
	assert.NoError(t, err)

	// Attempt to create a new UDPForwarder with a port that's out of range
	_, err = NewUDPForwarder("127.0.0.1:70000") // Port number out of range

	// Check that the error is not nil
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port")
}

func TestUDPForwarder_ForwardToUnreachableAddress(t *testing.T) {
	// Create a new UDPForwarder with a valid but unreachable address
	forwarder, err := NewUDPForwarder("203.0.113.1:12345") // TEST-NET-3 address, should be unreachable
	assert.NoError(t, err)

	// Attempt to forward a message
	err = forwarder.Forward([]byte("test message"))

	// This should not return an error for UDP, as it's connectionless
	assert.NoError(t, err)
}

func TestUDPForwarder_ConcurrentForwarding(t *testing.T) {
	// Start a mock UDP server
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	assert.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	assert.NoError(t, err)
	defer conn.Close()

	receivedMessages := make(map[string]bool)
	var receivedMu sync.Mutex

	done := make(chan bool)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				close(done)
				return
			}
			receivedMu.Lock()
			receivedMessages[string(buf[:n])] = true
			receivedMu.Unlock()
		}
	}()

	// Create a new UDPForwarder
	forwarder, err := NewUDPForwarder(conn.LocalAddr().String())
	assert.NoError(t, err)

	// Concurrently forward messages
	concurrency := 10
	messages := 100
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < messages; j++ {
				msg := fmt.Sprintf("test message %d-%d", workerID, j)
				err := forwarder.Forward([]byte(msg))
				assert.NoError(t, err)
				time.Sleep(time.Millisecond) // Add a small delay to reduce congestion
			}
		}(i)
	}

	// Wait for all goroutines to finish sending
	wg.Wait()

	// Wait a bit to ensure all messages are processed
	time.Sleep(2 * time.Second)

	// Stop the receiver
	conn.Close()
	<-done

	// Check received messages
	receivedCount := len(receivedMessages)
	expectedCount := concurrency * messages

	// Allow for some packet loss (e.g., 99% success rate)
	successRate := float64(receivedCount) / float64(expectedCount)
	assert.Greater(t, successRate, 0.99, "Success rate should be greater than 99%%")

	t.Logf("Received %d out of %d messages (%.2f%% success rate)",
		receivedCount, expectedCount, successRate*100)
}
