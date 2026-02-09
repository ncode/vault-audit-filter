package forwarder

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Forwarder is an interface for forwarding messages
type Forwarder interface {
	Forward([]byte) error
}

// UDPForwarder implements the Forwarder interface for UDP
type UDPForwarder struct {
	conn    *net.UDPConn
	timeout time.Duration
	mu      sync.Mutex
}

// NewUDPForwarder creates a new UDPForwarder
func NewUDPForwarder(address string) (*UDPForwarder, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	return &UDPForwarder{conn: conn}, nil
}

// SetTimeout configures a per-write deadline for UDP forwarding.
func (f *UDPForwarder) SetTimeout(timeout time.Duration) {
	f.timeout = timeout
}

// Forward sends the data to the UDP address
func (f *UDPForwarder) Forward(data []byte) error {
	if f.conn == nil {
		return errors.New("udp connection is nil")
	}
	if f.timeout > 0 {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = f.conn.SetWriteDeadline(time.Now().Add(f.timeout))
	}
	_, err := f.conn.Write(data)
	return err
}

// Close closes the UDP connection
func (f *UDPForwarder) Close() error {
	if f.conn != nil {
		return f.conn.Close()
	}
	return nil
}
