package forwarder

import (
	"net"
)

// Forwarder is an interface for forwarding messages
type Forwarder interface {
	Forward([]byte) error
}

// UDPForwarder implements the Forwarder interface for UDP
type UDPForwarder struct {
	conn *net.UDPConn
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

// Forward sends the data to the UDP address
func (f *UDPForwarder) Forward(data []byte) error {
	_, err := f.conn.Write(data)
	return err
}
