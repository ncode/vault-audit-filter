package forwarder

import (
	"net"
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

func TestUDPForwarder_ConcurrentForwarding(t *testing.T) {
	// Start a mock UDP server
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	assert.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	assert.NoError(t, err)
	defer conn.Close()

	receivedCount := 0
	go func() {
		buf := make([]byte, 1024)
		for {
			_, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			receivedCount++
		}
	}()

	// Create a new UDPForwarder
	forwarder, err := NewUDPForwarder(conn.LocalAddr().String())
	assert.NoError(t, err)

	// Concurrently forward messages
	concurrency := 10
	messages := 100
	done := make(chan bool)

	for i := 0; i < concurrency; i++ {
		go func() {
			for j := 0; j < messages; j++ {
				err := forwarder.Forward([]byte("test message"))
				assert.NoError(t, err)
			}
			done <- true
		}()
	}

	// Wait for all goroutines to finish
	for i := 0; i < concurrency; i++ {
		<-done
	}

	// Give some time for all messages to be received
	time.Sleep(100 * time.Millisecond)

	// Check if all messages were received
	assert.Equal(t, concurrency*messages, receivedCount)
}
