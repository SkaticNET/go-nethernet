package nethernet

import (
	"context"
	"net"
	"net/http"
	"sync"

	"github.com/pion/transport/v5"
	"github.com/pion/transport/v5/stdnet"
	"github.com/pion/webrtc/v4"
)

type captureContextKey struct{}

// CaptureEvent is a complete event emitted synchronously by one negotiated connection.
type CaptureEvent struct {
	Kind, Direction, Outcome        string
	Data                            []byte
	LocalAddr, RemoteAddr           string
	Bytes                           int
	Err                             string
	Method, URL                     string
	Headers                         http.Header
	StatusCode                      int
	RemoteHTTPAddr                  string
	Peer, Host, Protocol            string
	ContentLength                   int64
	Trailers                        http.Header
	Channel                         string
	Reliability                     uint8
	SegmentIndex, SegmentCount      int
	ParseOutcome, ReassemblyOutcome string
}

// Capture receives full, ordered capture events. A failing callback stops the
// operation that produced the event.
type Capture struct {
	Event      func(CaptureEvent) error
	mu         sync.Mutex
	dispatchMu sync.Mutex
	refs       int
	active     int
	closed     bool
	started    bool
	Done       func()
	Value      any
	failure    []func(error)
	failureErr error
}

// WithCapture associates an opt-in capture sink with a signaling or dial context.
func WithCapture(ctx context.Context, capture *Capture) context.Context {
	return context.WithValue(ctx, captureContextKey{}, capture)
}

func captureFromContext(ctx context.Context) *Capture {
	if ctx == nil {
		return nil
	}
	capture, _ := ctx.Value(captureContextKey{}).(*Capture)
	return capture
}

// CaptureFromContext returns the opt-in capture associated with ctx.
func CaptureFromContext(ctx context.Context) *Capture { return captureFromContext(ctx) }

// Emit appends a synchronous event to this capture.
func (c *Capture) Emit(event CaptureEvent) error { return c.emit(event) }

func (c *Capture) emit(event CaptureEvent) error {
	if c == nil || c.Event == nil {
		return nil
	}
	event.Data = append([]byte(nil), event.Data...)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.active++
	c.mu.Unlock()
	c.dispatchMu.Lock()
	err := c.Event(event)
	c.dispatchMu.Unlock()
	c.mu.Lock()
	failures := c.recordFailureLocked(err)
	c.active--
	done := c.finishLocked()
	c.mu.Unlock()
	for _, failure := range failures {
		failure(err)
	}
	if done != nil {
		done()
	}
	return err
}

func (c *Capture) SetFailureHandler(handler func(error)) {
	c.mu.Lock()
	c.failure = append(c.failure, handler)
	failureErr := c.failureErr
	c.mu.Unlock()
	if failureErr != nil && handler != nil {
		handler(failureErr)
	}
}

func (c *Capture) recordFailureLocked(err error) []func(error) {
	if err == nil || c.failureErr != nil {
		return nil
	}
	c.failureErr = err
	return append([]func(error){}, c.failure...)
}

// Retain transfers one independent lifetime reference to a Conn.
func (c *Capture) Retain() func() {
	release, _ := c.TryRetain()
	return release
}

// TryRetain acquires a lifetime reference unless the capture has already closed.
func (c *Capture) TryRetain() (func(), error) {
	if c == nil {
		return func() {}, nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return func() {}, net.ErrClosed
	}
	c.refs++
	c.started = true
	c.mu.Unlock()
	var once sync.Once
	return func() { once.Do(c.Release) }, nil
}

// Release closes the capture when its request and all owning Conns are done.
func (c *Capture) Release() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.refs > 0 {
		c.refs--
	}
	done := c.finishLocked()
	c.mu.Unlock()
	if done != nil {
		done()
	}
}

func (c *Capture) finishLocked() func() {
	if !c.started || c.refs != 0 || c.active != 0 || c.closed {
		return nil
	}
	c.closed = true
	return c.Done
}

// ConfigureCaptureSettings applies the per-session network and DTLS key-log hooks.
func ConfigureCaptureSettings(capture *Capture, setting *webrtc.SettingEngine) error {
	return ConfigureCaptureSettingsForPeer(capture, setting, "")
}

// ConfigureCaptureSettingsForPeer applies the per-session hooks with endpoint identity.
func ConfigureCaptureSettingsForPeer(capture *Capture, setting *webrtc.SettingEngine, peer string) error {
	if capture == nil {
		return nil
	}
	network, err := stdnet.NewNet()
	if err != nil {
		return err
	}
	setting.SetNet(captureNet{Net: network, capture: capture, peer: peer})
	setting.SetDTLSKeyLogWriter(&captureKeyLog{capture: capture, peer: peer})
	return nil
}

type captureNet struct {
	transport.Net
	capture *Capture
	peer    string
}

// CaptureNet returns a Pion network wrapper that records every UDP datagram.
func CaptureNet(network transport.Net, capture *Capture) transport.Net {
	if network == nil || capture == nil {
		return network
	}
	return captureNet{Net: network, capture: capture}
}

func (n captureNet) ListenUDP(network string, address *net.UDPAddr) (transport.UDPConn, error) {
	conn, err := n.Net.ListenUDP(network, address)
	if err != nil {
		return nil, err
	}
	return captureUDPConn{UDPConn: conn, capture: n.capture, peer: n.peer}, nil
}

func (n captureNet) ListenPacket(network, address string) (net.PacketConn, error) {
	conn, err := n.Net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return capturePacketConn{PacketConn: conn, capture: n.capture, peer: n.peer}, nil
}

type capturePacketConn struct {
	net.PacketConn
	capture *Capture
	peer    string
}

func (c capturePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	release, err := beginCaptureIO(c.capture)
	if err != nil {
		return 0, nil, err
	}
	defer release()
	n, addr, err := c.PacketConn.ReadFrom(p)
	e := c.capture.emit(CaptureEvent{Kind: "udp-datagram", Direction: captureDirection(c.peer, true), Peer: c.peer, Data: p[:n], Bytes: n, LocalAddr: addrString(c.LocalAddr()), RemoteAddr: addrString(addr), Outcome: ioOutcome(err), Err: errorString(err)})
	if err == nil {
		err = e
	}
	return n, addr, err
}
func (c capturePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	release, err := beginCaptureIO(c.capture)
	if err != nil {
		return 0, err
	}
	defer release()
	n, err := c.PacketConn.WriteTo(p, addr)
	e := c.capture.emit(CaptureEvent{Kind: "udp-datagram", Direction: captureDirection(c.peer, false), Peer: c.peer, Data: p[:n], Bytes: n, LocalAddr: addrString(c.LocalAddr()), RemoteAddr: addrString(addr), Outcome: ioOutcome(err), Err: errorString(err)})
	if err == nil {
		err = e
	}
	return n, err
}

func (n captureNet) DialUDP(network string, local, remote *net.UDPAddr) (transport.UDPConn, error) {
	conn, err := n.Net.DialUDP(network, local, remote)
	if err != nil {
		return nil, err
	}
	return captureUDPConn{UDPConn: conn, capture: n.capture, peer: n.peer}, nil
}

type captureUDPConn struct {
	transport.UDPConn
	capture *Capture
	peer    string
}

func (c captureUDPConn) ReadFrom(data []byte) (int, net.Addr, error) {
	release, err := beginCaptureIO(c.capture)
	if err != nil {
		return 0, nil, err
	}
	defer release()
	n, addr, err := c.UDPConn.ReadFrom(data)
	eventErr := c.capture.emit(CaptureEvent{Kind: "udp-datagram", Direction: captureDirection(c.peer, true), Peer: c.peer, Data: data[:n], Bytes: n, LocalAddr: addrString(c.LocalAddr()), RemoteAddr: addrString(addr), Outcome: ioOutcome(err), Err: errorString(err)})
	if err == nil {
		err = eventErr
	}
	return n, addr, err
}

func (c captureUDPConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	release, err := beginCaptureIO(c.capture)
	if err != nil {
		return 0, err
	}
	defer release()
	n, err := c.UDPConn.WriteTo(data, addr)
	eventErr := c.capture.emit(CaptureEvent{Kind: "udp-datagram", Direction: captureDirection(c.peer, false), Peer: c.peer, Data: data[:n], Bytes: n, LocalAddr: addrString(c.LocalAddr()), RemoteAddr: addrString(addr), Outcome: ioOutcome(err), Err: errorString(err)})
	if err == nil {
		err = eventErr
	}
	return n, err
}

func (c captureUDPConn) Read(data []byte) (int, error) {
	release, err := beginCaptureIO(c.capture)
	if err != nil {
		return 0, err
	}
	defer release()
	n, err := c.UDPConn.Read(data)
	eventErr := c.capture.emit(CaptureEvent{Kind: "udp-datagram", Direction: captureDirection(c.peer, true), Peer: c.peer, Data: data[:n], Bytes: n, LocalAddr: addrString(c.LocalAddr()), RemoteAddr: addrString(c.RemoteAddr()), Outcome: ioOutcome(err), Err: errorString(err)})
	if err == nil {
		err = eventErr
	}
	return n, err
}

func (c captureUDPConn) Write(data []byte) (int, error) {
	release, err := beginCaptureIO(c.capture)
	if err != nil {
		return 0, err
	}
	defer release()
	n, err := c.UDPConn.Write(data)
	eventErr := c.capture.emit(CaptureEvent{Kind: "udp-datagram", Direction: captureDirection(c.peer, false), Peer: c.peer, Data: data[:n], Bytes: n, LocalAddr: addrString(c.LocalAddr()), RemoteAddr: addrString(c.RemoteAddr()), Outcome: ioOutcome(err), Err: errorString(err)})
	if err == nil {
		err = eventErr
	}
	return n, err
}

func (c captureUDPConn) ReadFromUDP(p []byte) (int, *net.UDPAddr, error) {
	release, err := beginCaptureIO(c.capture)
	if err != nil {
		return 0, nil, err
	}
	defer release()
	n, addr, err := c.UDPConn.ReadFromUDP(p)
	e := c.capture.emit(CaptureEvent{Kind: "udp-datagram", Direction: captureDirection(c.peer, true), Peer: c.peer, Data: p[:n], Bytes: n, LocalAddr: addrString(c.LocalAddr()), RemoteAddr: addrString(addr), Outcome: ioOutcome(err), Err: errorString(err)})
	if err == nil {
		err = e
	}
	return n, addr, err
}
func (c captureUDPConn) WriteToUDP(p []byte, addr *net.UDPAddr) (int, error) {
	release, err := beginCaptureIO(c.capture)
	if err != nil {
		return 0, err
	}
	defer release()
	n, err := c.UDPConn.WriteToUDP(p, addr)
	e := c.capture.emit(CaptureEvent{Kind: "udp-datagram", Direction: captureDirection(c.peer, false), Peer: c.peer, Data: p[:n], Bytes: n, LocalAddr: addrString(c.LocalAddr()), RemoteAddr: addrString(addr), Outcome: ioOutcome(err), Err: errorString(err)})
	if err == nil {
		err = e
	}
	return n, err
}
func (c captureUDPConn) ReadMsgUDP(p, oob []byte) (int, int, int, *net.UDPAddr, error) {
	release, err := beginCaptureIO(c.capture)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	defer release()
	n, oobn, flags, addr, err := c.UDPConn.ReadMsgUDP(p, oob)
	e := c.capture.emit(CaptureEvent{Kind: "udp-datagram", Direction: captureDirection(c.peer, true), Peer: c.peer, Data: p[:n], Bytes: n, LocalAddr: addrString(c.LocalAddr()), RemoteAddr: addrString(addr), Outcome: ioOutcome(err), Err: errorString(err)})
	if err == nil {
		err = e
	}
	return n, oobn, flags, addr, err
}
func (c captureUDPConn) WriteMsgUDP(p, oob []byte, addr *net.UDPAddr) (int, int, error) {
	release, err := beginCaptureIO(c.capture)
	if err != nil {
		return 0, 0, err
	}
	defer release()
	n, oobn, err := c.UDPConn.WriteMsgUDP(p, oob, addr)
	e := c.capture.emit(CaptureEvent{Kind: "udp-datagram", Direction: captureDirection(c.peer, false), Peer: c.peer, Data: p[:n], Bytes: n, LocalAddr: addrString(c.LocalAddr()), RemoteAddr: addrString(addr), Outcome: ioOutcome(err), Err: errorString(err)})
	if err == nil {
		err = e
	}
	return n, oobn, err
}

func beginCaptureIO(capture *Capture) (func(), error) {
	return capture.TryRetain()
}

func captureDirection(peer string, inbound bool) string {
	if peer == "downstream" {
		if inbound {
			return "client-to-relay"
		}
		return "relay-to-client"
	}
	if peer == "upstream" {
		if inbound {
			return "server-to-relay"
		}
		return "relay-to-server"
	}
	if inbound {
		return "inbound"
	}
	return "outbound"
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func ioOutcome(err error) string {
	if err == nil {
		return "ok"
	}
	return "error"
}

// captureKeyLog serializes TLS key-log writes into the same session event stream.
type captureKeyLog struct {
	mu      sync.Mutex
	capture *Capture
	peer    string
}

func (w *captureKeyLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.capture.emit(CaptureEvent{Kind: "dtls-keylog", Direction: "local", Peer: w.peer, Data: p, Bytes: len(p), Outcome: "ok"}); err != nil {
		return 0, err
	}
	return len(p), nil
}
