package nethernet

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/pion/transport/v5/stdnet"
	"testing"
)

func TestCaptureContextAndCopiesEventBytes(t *testing.T) {
	var got CaptureEvent
	capture := &Capture{Event: func(event CaptureEvent) error { got = event; return nil }}
	ctx := WithCapture(context.Background(), capture)
	data := []byte{1, 2, 3}
	if err := captureFromContext(ctx).emit(CaptureEvent{Kind: "udp-datagram", Data: data}); err != nil {
		t.Fatal(err)
	}
	data[0] = 9
	if got.Data[0] != 1 {
		t.Fatalf("capture retained mutable event data: %v", got.Data)
	}
	want := errors.New("capture failed")
	capture.Event = func(CaptureEvent) error { return want }
	if err := capture.emit(CaptureEvent{}); !errors.Is(err, want) {
		t.Fatalf("emit error = %v, want %v", err, want)
	}
}

func TestCaptureFailurePreventsInboundMessageDelivery(t *testing.T) {
	for _, kind := range []string{"data-channel-segment", "data-channel-parse"} {
		t.Run(kind, func(t *testing.T) {
			for _, queue := range []struct {
				name string
				size int
			}{{"no reader", 0}, {"ready receiver", 1}} {
				t.Run(queue.name, func(t *testing.T) {
					captureErr := errors.New("controlled inbound capture failure")
					capture := &Capture{Event: func(event CaptureEvent) error {
						if event.Kind == kind {
							return captureErr
						}
						return nil
					}}
					channel := &dataChannel{
						conn:        &Conn{capture: capture, capturePeer: "downstream"},
						reliability: MessageReliabilityReliable,
						message:     &message{},
						packets:     make(chan []byte, queue.size),
						close:       make(chan struct{}),
					}
					t.Cleanup(func() { close(channel.close) })
					returned := make(chan error, 1)
					go func() {
						_, err := channel.handleMessage([]byte{0, 'a'}, false)
						returned <- err
					}()
					select {
					case err := <-returned:
						if !errors.Is(err, captureErr) {
							t.Fatalf("handleMessage() error = %v, want capture failure", err)
						}
					case <-time.After(time.Second):
						t.Fatal("capture failure blocked waiting for a packet reader")
					}
					select {
					case packet := <-channel.packets:
						t.Fatalf("uncaptured packet delivered: %x", packet)
					default:
					}
				})
			}
		})
	}
}

func TestCaptureRecordsParseBeforeInboundMessageDeliveryWithoutObserver(t *testing.T) {
	var events []CaptureEvent
	channel := &dataChannel{
		conn:        &Conn{capturePeer: "downstream"},
		reliability: MessageReliabilityReliable,
		message:     &message{},
		packets:     make(chan []byte, 1),
		close:       make(chan struct{}),
	}
	channel.conn.capture = &Capture{Event: func(event CaptureEvent) error {
		if len(channel.packets) != 0 {
			t.Error("packet delivered before its capture records")
		}
		events = append(events, event)
		return nil
	}}
	for _, segment := range [][]byte{{1, 'a'}, {0, 'b'}} {
		if _, err := channel.handleMessage(segment, false); err != nil {
			t.Fatal(err)
		}
	}
	if packet := <-channel.packets; !bytes.Equal(packet, []byte("ab")) {
		t.Fatalf("reassembled packet = %x", packet)
	}
	if _, err := channel.handleMessage([]byte{1}, false); err == nil {
		t.Fatal("malformed segment was accepted")
	}
	if len(events) != 6 || events[1].ParseOutcome != string(MessageParseValid) || events[1].ReassemblyOutcome != string(MessageReassemblyPending) || events[1].SegmentCount != 2 || events[3].SegmentIndex != 1 || events[3].ReassemblyOutcome != string(MessageReassemblyComplete) || events[5].ParseOutcome != string(MessageParseInvalid) {
		t.Fatalf("parse/reassembly records = %#v", events)
	}
}

func TestCaptureEmitSerializesConcurrentCallbacks(t *testing.T) {
	firstEntered, releaseFirst := make(chan struct{}), make(chan struct{})
	secondEntered := make(chan struct{})
	var order []string
	var orderMu sync.Mutex
	capture := &Capture{Event: func(event CaptureEvent) error {
		if event.Outcome == "first" {
			close(firstEntered)
			<-releaseFirst
		} else {
			close(secondEntered)
		}
		orderMu.Lock()
		order = append(order, event.Outcome)
		orderMu.Unlock()
		return nil
	}}
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- capture.Emit(CaptureEvent{Outcome: "first"}) }()
	<-firstEntered
	secondStarted := make(chan struct{})
	go func() { close(secondStarted); secondDone <- capture.Emit(CaptureEvent{Outcome: "second"}) }()
	<-secondStarted
	select {
	case <-secondEntered:
		t.Fatal("second callback ran concurrently with the first callback")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	orderMu.Lock()
	defer orderMu.Unlock()
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("callback order = %v", order)
	}
}

type blockedPacketConn struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *blockedPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	close(c.started)
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (c *blockedPacketConn) WriteTo([]byte, net.Addr) (int, error) { return 0, net.ErrClosed }
func (c *blockedPacketConn) Close() error                          { c.once.Do(func() { close(c.closed) }); return nil }
func (c *blockedPacketConn) LocalAddr() net.Addr                   { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *blockedPacketConn) SetDeadline(time.Time) error           { return nil }
func (c *blockedPacketConn) SetReadDeadline(time.Time) error       { return nil }
func (c *blockedPacketConn) SetWriteDeadline(time.Time) error      { return nil }

func TestCaptureWaitsForBlockedUDPReadToRecordCloseOutcome(t *testing.T) {
	started, done := make(chan struct{}), make(chan struct{})
	var events []CaptureEvent
	var eventsMu sync.Mutex
	capture := &Capture{Done: func() { close(done) }, Event: func(event CaptureEvent) error {
		eventsMu.Lock()
		events = append(events, event)
		eventsMu.Unlock()
		return nil
	}}
	releaseOwner := capture.Retain()
	base := &blockedPacketConn{started: started, closed: make(chan struct{})}
	wrapper := capturePacketConn{PacketConn: base, capture: capture, peer: "upstream"}
	readDone := make(chan error, 1)
	go func() { _, _, err := wrapper.ReadFrom(make([]byte, 32)); readDone <- err }()
	<-started
	releaseOwner()
	select {
	case <-done:
		t.Fatal("capture closed before the in-flight UDP read was recorded")
	default:
	}
	_ = wrapper.Close()
	if err := <-readDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("blocked read error = %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capture did not close after the UDP read completed")
	}
	eventsMu.Lock()
	defer eventsMu.Unlock()
	if len(events) != 1 || events[0].Kind != "udp-datagram" || events[0].Outcome != "error" {
		t.Fatalf("final UDP read outcome not captured: %#v", events)
	}
}

func TestCaptureUDPRecordsBothDirectionsWithoutChangingBytes(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	base, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}
	var events []CaptureEvent
	capture := &Capture{Event: func(event CaptureEvent) error { events = append(events, event); return nil }}
	releaseCapture := capture.Retain()
	defer releaseCapture()
	wrapped, err := (captureNet{Net: base, capture: capture, peer: "upstream"}).ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	sent := []byte{0x16, 0xfe, 0xfd, 0x00, 0xff}
	if n, err := wrapped.WriteToUDP(sent, peer.LocalAddr().(*net.UDPAddr)); err != nil || n != len(sent) {
		t.Fatalf("wrapped write = %d, %v", n, err)
	}
	buf := make([]byte, 32)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], sent) {
		t.Fatalf("wire bytes = %x, %v", buf[:n], err)
	}
	received := []byte{0x01, 0x02, 0x03, 0x04}
	if _, err := peer.WriteToUDP(received, wrapped.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = wrapped.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = wrapped.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], received) {
		t.Fatalf("read bytes = %x, %v", buf[:n], err)
	}
	if len(events) != 2 || events[0].Direction != "relay-to-server" || events[1].Direction != "server-to-relay" || !bytes.Equal(events[0].Data, sent) || !bytes.Equal(events[1].Data, received) {
		t.Fatalf("capture events do not preserve UDP exchange: %#v", events)
	}
}

func TestCaptureDTLSKeyLogIncludesPeerAndFullRecord(t *testing.T) {
	var got CaptureEvent
	capture := &Capture{Event: func(event CaptureEvent) error { got = event; return nil }}
	writer := &captureKeyLog{capture: capture, peer: "upstream"}
	line := []byte("CLIENT_RANDOM synthetic-client-random synthetic-secret\\n")
	n, err := writer.Write(line)
	if err != nil || n != len(line) {
		t.Fatalf("key log write = %d, %v", n, err)
	}
	if got.Kind != "dtls-keylog" || got.Peer != "upstream" || !bytes.Equal(got.Data, line) {
		t.Fatalf("key log event = %#v", got)
	}
}
