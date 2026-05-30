package auditserver

import (
	"bytes"
	"log/slog"

	"github.com/panjf2000/gnet/v2"
)

type frameHandler interface {
	handleFrame([]byte) gnet.Action
}

type transportAdapter struct {
	protocol string
	logger   *slog.Logger
	handler  frameHandler
}

func newTransportAdapter(protocol string, logger *slog.Logger, handler frameHandler) transportAdapter {
	return transportAdapter{
		protocol: protocol,
		logger:   logger,
		handler:  handler,
	}
}

func (t transportAdapter) OnTraffic(c gnet.Conn) gnet.Action {
	frame, err := c.Next(-1)
	if err != nil {
		if t.logger != nil {
			t.logger.Error("Error reading frame", "error", err)
		}
		return gnet.Close
	}
	if t.protocol == "tcp" {
		var carryover []byte
		if ctx := c.Context(); ctx != nil {
			if b, ok := ctx.([]byte); ok {
				carryover = b
			}
		}

		remaining := t.handleTCPStream(frame, carryover)
		if len(remaining) == 0 {
			c.SetContext(nil)
			return gnet.None
		}
		c.SetContext(append([]byte(nil), remaining...))
		return gnet.None
	}
	return t.handleFrame(frame)
}

func (t transportAdapter) handleTCPStream(frame []byte, carryover []byte) []byte {
	buffer := append([]byte(nil), carryover...)
	if len(frame) > 0 {
		buffer = append(buffer, frame...)
	}

	for {
		sep := bytes.IndexByte(buffer, '\n')
		if sep < 0 {
			return buffer
		}

		rawLine := buffer[:sep]
		line := bytes.TrimSuffix(rawLine, []byte{'\r'})
		if len(line) > 0 {
			_ = t.handleFrame(line)
		}

		if sep == len(buffer)-1 {
			buffer = buffer[:0]
		} else {
			buffer = buffer[sep+1:]
		}
	}
}

func (t transportAdapter) handleFrame(frame []byte) gnet.Action {
	if t.handler == nil {
		return gnet.Close
	}
	return t.handler.handleFrame(frame)
}
