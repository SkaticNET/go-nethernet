package nethernet

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
)

type closeTestNegotiator struct{}

func (closeTestNegotiator) handleClose(*Conn) {}
func (closeTestNegotiator) log() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestConnCloseCaptureFailureCanReenterClose(t *testing.T) {
	var events atomic.Int32
	done := make(chan struct{})
	capture := &Capture{Event: func(event CaptureEvent) error {
		if event.Kind == "connection-state" && event.Outcome == "closed" {
			events.Add(1)
			return errors.New("synthetic final write failure")
		}
		return nil
	}, Done: func() { close(done) }}
	release, err := capture.TryRetain()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := newConn(webrtc.NewAPI(), webrtc.ICEGatherOptions{}, 1, "remote", "local", closeTestNegotiator{}, ErrorCodeGenericFailure)
	if err != nil {
		t.Fatal(err)
	}
	conn.capture = capture
	conn.capturePeer = "downstream"
	conn.releaseCapture = release
	capture.SetFailureHandler(func(error) { _ = conn.Close() })

	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case err := <-closed:
		if err == nil || err.Error() != "synthetic final write failure" {
			t.Fatalf("Close() error = %v, want final capture write failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Conn.Close deadlocked when failure handler reentered Close")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capture did not reach terminal close")
	}
	if got := events.Load(); got != 1 {
		t.Fatalf("final connection-state events = %d, want exactly one", got)
	}
}

func TestCaptureParseFailureCanCloseConnectionBeforeDelivery(t *testing.T) {
	api := webrtc.NewAPI()
	conn, err := newConn(api, webrtc.ICEGatherOptions{}, 1, "remote", "local", closeTestNegotiator{}, ErrorCodeGenericFailure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	peer, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	dc, err := peer.CreateDataChannel(MessageReliabilityReliable.Parameters().Label, nil)
	if err != nil {
		t.Fatal(err)
	}
	channel := wrapDataChannel(dc, MessageReliabilityReliable, conn)
	conn.storeChannel(MessageReliabilityReliable, channel)
	captureErr := errors.New("controlled parse capture failure")
	conn.capture = &Capture{Event: func(event CaptureEvent) error {
		if event.Kind == "data-channel-parse" {
			return captureErr
		}
		return nil
	}}
	conn.capture.SetFailureHandler(func(error) { _ = conn.Close() })
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
		t.Fatal("capture failure deadlocked with connection teardown")
	}
	select {
	case <-conn.Context().Done():
	default:
		t.Fatal("capture failure did not close the connection")
	}
}

func TestClosedWriteError(t *testing.T) {
	t.Run("preserves cause", func(t *testing.T) {
		cause := errors.New("nethernet transport closed")
		err := closedWriteError(cause)
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closedWriteError(cause) = %v, want net.ErrClosed", err)
		}
		if !errors.Is(err, cause) {
			t.Fatalf("closedWriteError(cause) = %v, want cause %v", err, cause)
		}
	})

	t.Run("already closed", func(t *testing.T) {
		err := closedWriteError(net.ErrClosed)
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closedWriteError(net.ErrClosed) = %v, want net.ErrClosed", err)
		}
	})
}

func TestConnReadKeepsRemainderWhenBufferIsShort(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	conn := &Conn{ctx: ctx}
	packets := make(chan []byte, 1)
	conn.storeChannel(MessageReliabilityReliable, &dataChannel{packets: packets})
	packets <- []byte("hello")

	b := make([]byte, 2)
	n, err := conn.Read(b)
	if err != nil {
		t.Fatalf("first Read() error = %v, want nil", err)
	}
	if got := string(b[:n]); got != "he" {
		t.Fatalf("first Read() = %q, want %q", got, "he")
	}

	n, err = conn.Read(b)
	if err != nil {
		t.Fatalf("second Read() error = %v, want nil", err)
	}
	if got := string(b[:n]); got != "ll" {
		t.Fatalf("second Read() = %q, want %q", got, "ll")
	}

	n, err = conn.Read(b)
	if err != nil {
		t.Fatalf("third Read() error = %v, want nil", err)
	}
	if got := string(b[:n]); got != "o" {
		t.Fatalf("third Read() = %q, want %q", got, "o")
	}
}

func TestIsTerminalICEState(t *testing.T) {
	for state, terminal := range map[webrtc.ICETransportState]bool{
		webrtc.ICETransportStateUnknown:      false,
		webrtc.ICETransportStateNew:          false,
		webrtc.ICETransportStateChecking:     false,
		webrtc.ICETransportStateConnected:    false,
		webrtc.ICETransportStateCompleted:    false,
		webrtc.ICETransportStateDisconnected: false,
		webrtc.ICETransportStateFailed:       true,
		webrtc.ICETransportStateClosed:       true,
	} {
		if got := isTerminalICEState(state); got != terminal {
			t.Errorf("isTerminalICEState(%s) = %t, want %t", state, got, terminal)
		}
	}
}

func TestDescriptionDefaultCandidate(t *testing.T) {
	relay := webrtc.ICECandidate{
		Protocol:  webrtc.ICEProtocolUDP,
		Component: uint16(webrtc.ICEComponentRTP),
		Typ:       webrtc.ICECandidateTypeRelay,
		Address:   "203.0.113.1",
		Port:      40000,
	}
	ipv6Relay := webrtc.ICECandidate{
		Protocol:  webrtc.ICEProtocolUDP,
		Component: uint16(webrtc.ICEComponentRTP),
		Typ:       webrtc.ICECandidateTypeRelay,
		Address:   "2001:db8::2",
		Port:      40004,
	}
	ipv4Reflexive := webrtc.ICECandidate{
		Protocol:  webrtc.ICEProtocolUDP,
		Component: uint16(webrtc.ICEComponentRTP),
		Typ:       webrtc.ICECandidateTypeSrflx,
		Address:   "203.0.113.2",
		Port:      40002,
	}
	ipv4Host := webrtc.ICECandidate{
		Protocol:  webrtc.ICEProtocolUDP,
		Component: uint16(webrtc.ICEComponentRTP),
		Typ:       webrtc.ICECandidateTypeHost,
		Address:   "192.0.2.1",
		Port:      40003,
	}
	ipv4Host2 := ipv4Host
	ipv4Host2.Address = "192.0.2.2"
	ipv4Host2.Port = 40005
	hostname := ipv4Host
	hostname.Address = "host.local"
	hostnameRelay := relay
	hostnameRelay.Address = "relay.local"
	tcpHost := ipv4Host
	tcpHost.Protocol = webrtc.ICEProtocolTCP
	rtcpHost := ipv4Host
	rtcpHost.Component = uint16(webrtc.ICEComponentRTCP)

	for _, test := range []struct {
		name       string
		candidates []webrtc.ICECandidate
		want       webrtc.ICECandidate
		wantOK     bool
	}{
		{
			name:       "relay only",
			candidates: []webrtc.ICECandidate{relay},
			want:       relay,
			wantOK:     true,
		},
		{
			name:       "IPv4 replaces higher-preference IPv6",
			candidates: []webrtc.ICECandidate{ipv6Relay, ipv4Host},
			want:       ipv4Host,
			wantOK:     true,
		},
		{
			name:       "IPv4 remains over higher-preference IPv6",
			candidates: []webrtc.ICECandidate{ipv4Host, ipv6Relay},
			want:       ipv4Host,
			wantOK:     true,
		},
		{
			name:       "relay wins within address family",
			candidates: []webrtc.ICECandidate{ipv4Host, ipv4Reflexive, relay},
			want:       relay,
			wantOK:     true,
		},
		{
			name:       "server reflexive replaces host within address family",
			candidates: []webrtc.ICECandidate{ipv4Host, ipv4Reflexive},
			want:       ipv4Reflexive,
			wantOK:     true,
		},
		{
			name:       "lower preference loses within address family",
			candidates: []webrtc.ICECandidate{relay, ipv4Reflexive, ipv4Host},
			want:       relay,
			wantOK:     true,
		},
		{
			name:       "equal preference keeps first candidate",
			candidates: []webrtc.ICECandidate{ipv4Host, ipv4Host2},
			want:       ipv4Host,
			wantOK:     true,
		},
		{
			name:       "hostname candidate participates in selection",
			candidates: []webrtc.ICECandidate{hostname},
			want:       hostname,
			wantOK:     true,
		},
		{
			name:       "higher-preference hostname replaces IPv4",
			candidates: []webrtc.ICECandidate{ipv4Host, hostnameRelay},
			want:       hostnameRelay,
			wantOK:     true,
		},
		{
			name:       "IPv4 replaces higher-preference hostname",
			candidates: []webrtc.ICECandidate{hostnameRelay, ipv4Host},
			want:       ipv4Host,
			wantOK:     true,
		},
		{
			name:       "TCP candidate is not eligible",
			candidates: []webrtc.ICECandidate{tcpHost},
		},
		{
			name:       "RTCP candidate is not eligible",
			candidates: []webrtc.ICECandidate{rtcpHost},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := (description{candidates: test.candidates}).defaultCandidate()
			if ok != test.wantOK {
				t.Fatalf("defaultCandidate() selection = %t, want %t", ok, test.wantOK)
			}
			if ok && got != test.want {
				t.Fatalf("defaultCandidate() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestTypePreference(t *testing.T) {
	for _, test := range []struct {
		candidateType webrtc.ICECandidateType
		want          uint16
	}{
		{candidateType: webrtc.ICECandidateTypeHost, want: 1},
		{candidateType: webrtc.ICECandidateTypeSrflx, want: 2},
		{candidateType: webrtc.ICECandidateTypeRelay, want: 3},
		{candidateType: webrtc.ICECandidateTypePrflx, want: 0},
	} {
		if got := typePreference(webrtc.ICECandidate{Typ: test.candidateType}); got != test.want {
			t.Errorf("typePreference(%s) = %d, want %d", test.candidateType, got, test.want)
		}
	}
}

func TestDescriptionEncodeKeepsDummyAddressForHostnameCandidate(t *testing.T) {
	data, err := (description{
		ice: webrtc.ICEParameters{UsernameFragment: "ufrag", Password: "password"},
		dtls: webrtc.DTLSParameters{Fingerprints: []webrtc.DTLSFingerprint{{
			Algorithm: "sha-256",
			Value:     "fingerprint",
		}}},
		candidates: []webrtc.ICECandidate{
			{
				Protocol:  webrtc.ICEProtocolUDP,
				Component: uint16(webrtc.ICEComponentRTP),
				Typ:       webrtc.ICECandidateTypeHost,
				Address:   "192.0.2.1",
				Port:      40000,
			},
			{
				Protocol:  webrtc.ICEProtocolUDP,
				Component: uint16(webrtc.ICEComponentRTP),
				Typ:       webrtc.ICECandidateTypeRelay,
				Address:   "relay.local",
				Port:      40001,
			},
		},
	}).encode()
	if err != nil {
		t.Fatalf("encode() error = %v", err)
	}

	var session sdp.SessionDescription
	if err := session.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal SDP: %v", err)
	}
	media := session.MediaDescriptions[0]
	if media.MediaName.Port.Value != 9 {
		t.Fatalf("media port = %d, want 9", media.MediaName.Port.Value)
	}
	if got := media.ConnectionInformation.Address.Address; got != "0.0.0.0" {
		t.Fatalf("connection address = %q, want 0.0.0.0", got)
	}
}

func TestParseDescriptionRejectsMessageSizesWithoutFragmentPayload(t *testing.T) {
	for _, max := range []string{"0", "1"} {
		t.Run(max, func(t *testing.T) {
			media := &sdp.MediaDescription{}
			media.WithValueAttribute("ice-ufrag", "ufrag")
			media.WithValueAttribute("ice-pwd", "password")
			media.WithFingerprint("sha-256", "fingerprint")
			media.WithValueAttribute("setup", "actpass")
			media.WithValueAttribute("max-message-size", max)

			_, err := parseDescription(&sdp.SessionDescription{
				MediaDescriptions: []*sdp.MediaDescription{media},
			})
			if err == nil {
				t.Fatalf("parseDescription() error = nil, want error for max-message-size %s", max)
			}
		})
	}
}
