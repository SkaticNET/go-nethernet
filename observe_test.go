package nethernet

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
)

func TestSummarizeRemoteDescriptionKeepsOnlyBoundedStructure(t *testing.T) {
	d := &sdp.SessionDescription{
		Attributes: []sdp.Attribute{
			{Key: "group", Value: "BUNDLE 0"},
			{Key: "ice-options", Value: "trickle"},
		},
		MediaDescriptions: []*sdp.MediaDescription{{
			Attributes: []sdp.Attribute{{Key: "ice-options", Value: "trickle"}},
		}},
	}
	parsed := &description{
		ice:        webrtc.ICEParameters{UsernameFragment: "u", Password: "p"},
		dtls:       webrtc.DTLSParameters{Role: webrtc.DTLSRoleClient, Fingerprints: []webrtc.DTLSFingerprint{{Algorithm: "sha-256"}}},
		sctp:       webrtc.SCTPCapabilities{MaxMessageSize: 1200},
		candidates: make([]webrtc.ICECandidate, 3),
	}

	stats := summarizeRemoteDescription(d, parsed)
	if stats.MediaSections != 1 || stats.CandidateCount != 3 || !stats.HasICECredentials || !stats.HasFingerprint || !stats.HasSCTP || !stats.HasBundle || !stats.HasTrickle || stats.DTLSRole != "client" {
		t.Fatalf("remote description structure was not summarized: %+v", stats)
	}
}

func TestListenerObservesIncomingAndOutgoingDataChannelSegments(t *testing.T) {
	client, server := newMemorySignalingPair("1", "2")
	defer client.close()
	defer server.close()

	events := make(chan DataChannelMessageObservation, 8)
	_, clientConn, serverConn := dialAcceptedListenerWithConfig(t, client, server, ListenConfig{
		AllowAnonymous: true,
		ObserveDataChannelMessage: func(event DataChannelMessageObservation) {
			// The observer may retain and mutate its copy without changing the packet path.
			recorded := event
			recorded.Data = bytes.Clone(event.Data)
			recorded.ReassembledData = bytes.Clone(event.ReassembledData)
			if len(event.Data) > 0 {
				event.Data[0] ^= 0xff
			}
			if len(event.ReassembledData) > 0 {
				event.ReassembledData[0] ^= 0xff
			}
			events <- recorded
		},
	})
	clientConn.maxSegmentPayload.Store(4)
	serverConn.maxSegmentPayload.Store(4)
	payload := []byte("hello")

	checkDirection := func(sender, receiver *Conn, wantDirection DataChannelMessageDirection) {
		t.Helper()
		received := make(chan []byte, 1)
		receiveErr := make(chan error, 1)
		go func() {
			data, err := receiver.Receive(MessageReliabilityReliable)
			if err != nil {
				receiveErr <- err
				return
			}
			received <- data
		}()
		if n, err := sender.Send(payload, MessageReliabilityReliable); err != nil || n != len(payload) {
			t.Fatalf("Send() = (%d, %v), want (%d, nil)", n, err, len(payload))
		}
		select {
		case got := <-received:
			if !bytes.Equal(got, payload) {
				t.Fatalf("Receive() = %q, want %q", got, payload)
			}
		case err := <-receiveErr:
			t.Fatalf("Receive() error = %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Receive() timed out")
		}

		for index := range 2 {
			select {
			case event := <-events:
				if event.ConnectionID != serverConn.id || event.NetworkID != serverConn.networkID || event.Direction != wantDirection {
					t.Fatalf("event identity = (%d, %q), want (%d, %q)", event.ConnectionID, event.Direction, serverConn.id, wantDirection)
				}
				if event.Reliability != MessageReliabilityReliable || !event.Ordered || !event.HasStreamID {
					t.Fatalf("event channel metadata = %+v", event)
				}
				if event.ParseOutcome != MessageParseValid || event.SegmentCount != 2 || event.SegmentIndex != index {
					t.Fatalf("event segment metadata = %+v", event)
				}
				segmentStart := index * 4
				segmentEnd := min(len(payload), segmentStart+4)
				wantData := append([]byte{byte(1 - index)}, payload[segmentStart:segmentEnd]...)
				if !bytes.Equal(event.Data, wantData) {
					t.Fatalf("event raw data = %v, want %v", event.Data, wantData)
				}
				if wantDirection == DataChannelMessageInbound {
					if index == 0 {
						if event.ReassemblyOutcome != MessageReassemblyPending || len(event.ReassembledData) != 0 {
							t.Fatalf("first event reassembly = %+v", event)
						}
					} else if event.ReassemblyOutcome != MessageReassemblyComplete || !bytes.Equal(event.ReassembledData, payload) {
						t.Fatalf("final event reassembly = %+v", event)
					}
				} else if event.ReassemblyOutcome != MessageReassemblyNotApplicable || len(event.ReassembledData) != 0 {
					t.Fatalf("outgoing event reassembly = %+v", event)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("data-channel observation timed out")
			}
		}
	}

	checkDirection(clientConn, serverConn, DataChannelMessageInbound)
	checkDirection(serverConn, clientConn, DataChannelMessageOutbound)
}

func TestListenerObservesLifecycleAndOwnedTransportSnapshots(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)

	snapshots := make(chan TransportSnapshotObservation, 256)
	states := make(chan ConnectionStateObservation, 4)
	_, _, serverConn := dialAcceptedListenerWithConfig(t, client, server, ListenConfig{
		AllowAnonymous: true,
		ObserveTransportSnapshot: func(event TransportSnapshotObservation) {
			snapshots <- event
		},
		ObserveConnectionState: func(event ConnectionStateObservation) {
			states <- event
		},
	})

	select {
	case event := <-states:
		if event.ConnectionID != serverConn.id || event.NetworkID != serverConn.networkID || event.State != ConnectionStateReady || event.Err != nil {
			t.Fatal("listener did not report the correlated ready state")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener ready state was not observed")
	}

	var observed TransportSnapshot
	deadline := time.After(5 * time.Second)
forSnapshots:
	for {
		select {
		case event := <-snapshots:
			if event.ConnectionID == serverConn.id && event.NetworkID == serverConn.networkID && event.Snapshot.HasLocalDescription && event.Snapshot.HasRemoteDescription && len(event.Snapshot.LocalCandidates) > 0 && len(event.Snapshot.RemoteCandidates) > 0 && event.Snapshot.SelectedCandidatePair != nil && len(event.Snapshot.RemoteCertificate) > 0 && len(event.Snapshot.SCTPInit) > 0 {
				observed = event.Snapshot
				break forSnapshots
			}
		case <-deadline:
			t.Fatal("complete transport snapshot was not observed")
		}
	}
	if len(observed.LocalICEParameters.UsernameFragment) == 0 || len(observed.RemoteICEParameters.UsernameFragment) == 0 || len(observed.LocalDTLSParameters.Fingerprints) == 0 || len(observed.RemoteDTLSParameters.Fingerprints) == 0 {
		t.Fatal("transport snapshot omitted negotiated ICE or DTLS parameters")
	}
	if !bytes.Equal(observed.SCTPInit, serverConn.sctpInit) {
		t.Fatal("transport snapshot did not use the SCTP INIT cached before transport start")
	}
	if observed.ICEStats.BytesSent == 0 || observed.ICEStats.BytesReceived == 0 {
		t.Fatal("transport snapshot omitted ICE transport byte counters")
	}

	// A retained callback event must not share mutable Pion-owned storage or pointers.
	baseline := serverConn.transportSnapshotObservation().Snapshot
	mutated := observed
	mutated.LocalCandidates[0].Address = "mutated"
	mutated.RemoteCandidates[0].Address = "mutated"
	mutated.LocalDTLSParameters.Fingerprints[0].Value = "mutated"
	mutated.RemoteDTLSParameters.Fingerprints[0].Value = "mutated"
	mutated.SelectedCandidatePair.Local.Address = "mutated"
	mutated.SelectedCandidatePair.Remote.Address = "mutated"
	mutated.RemoteCertificate[0] ^= 0xff
	mutated.SCTPInit[0] ^= 0xff
	if mutated.SCTPStats.Metadata != nil {
		mutated.SCTPStats.Metadata.MessageInterleavingEnabled = !mutated.SCTPStats.Metadata.MessageInterleavingEnabled
	}
	after := serverConn.transportSnapshotObservation().Snapshot
	if after.LocalCandidates[0].Address == "mutated" || after.RemoteCandidates[0].Address == "mutated" || after.LocalDTLSParameters.Fingerprints[0].Value == "mutated" || after.RemoteDTLSParameters.Fingerprints[0].Value == "mutated" || after.SelectedCandidatePair.Local.Address == "mutated" || after.SelectedCandidatePair.Remote.Address == "mutated" || bytes.Equal(after.RemoteCertificate, mutated.RemoteCertificate) || bytes.Equal(after.SCTPInit, mutated.SCTPInit) {
		t.Fatal("transport snapshot shared mutable storage with its observer")
	}
	if baseline.SCTPStats.Metadata != nil && after.SCTPStats.Metadata != nil && after.SCTPStats.Metadata.MessageInterleavingEnabled != baseline.SCTPStats.Metadata.MessageInterleavingEnabled {
		t.Fatal("transport snapshot shared SCTP metadata with its observer")
	}

	if err := serverConn.Close(); err != nil {
		t.Fatalf("Conn.Close() error = %v", err)
	}
	awaitSnapshotIdle(t, serverConn)
	var closeSnapshot *TransportSnapshot
	deadline = time.After(5 * time.Second)
	for closeSnapshot == nil {
		select {
		case event := <-snapshots:
			if event.ConnectionID == serverConn.id && event.Snapshot.Phase == TransportSnapshotPhasePreClose {
				copy := event.Snapshot
				closeSnapshot = &copy
			}
		case <-deadline:
			t.Fatal("pre-close snapshot was not observed")
		}
	}
	if !closeSnapshot.HasLocalDescription || !closeSnapshot.HasRemoteDescription {
		t.Fatal("pre-close snapshot omitted descriptions sampled before teardown")
	}
	select {
	case event := <-states:
		if event.ConnectionID != serverConn.id || event.NetworkID != serverConn.networkID || event.State != ConnectionStateClosed {
			t.Fatal("listener did not report the correlated closed state")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener closed state was not observed")
	}
}

func TestListenerDoesNotRetainRawDescriptionsWithoutSnapshotObserver(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	_, _, conn := dialAcceptedListenerWithConfig(t, client, server, ListenConfig{AllowAnonymous: true})
	if conn.localDescription != "" || conn.remoteDescription != "" || conn.hasRemoteDescription {
		t.Fatal("listener retained raw SDP without a transport snapshot observer")
	}
	if conn.remoteICEParameters.UsernameFragment != "" || conn.remoteICEParameters.Password != "" || len(conn.remoteDTLSParameters.Fingerprints) != 0 {
		t.Fatal("listener retained remote ICE credentials or DTLS fingerprints without a transport snapshot observer")
	}
	if conn.snapshotWake != nil || conn.lifecycleEvents != nil {
		t.Fatal("listener started observer workers when no observers were configured")
	}
}

func TestConnectionLifecycleNeverReportsReadyAfterClosed(t *testing.T) {
	for range 100 {
		var (
			mu     sync.Mutex
			states []ConnectionState
		)
		conn := &Conn{id: 42}
		conn.startLifecycleObserver(func(event ConnectionStateObservation) {
			mu.Lock()
			states = append(states, event.State)
			mu.Unlock()
		})
		start := make(chan struct{})
		var writers sync.WaitGroup
		writers.Add(2)
		go func() {
			defer writers.Done()
			<-start
			conn.emitConnectionReady()
		}()
		go func() {
			defer writers.Done()
			<-start
			conn.emitConnectionClosed(nil)
		}()
		close(start)
		writers.Wait()
		<-conn.lifecycleDone
		mu.Lock()
		got := append([]ConnectionState(nil), states...)
		mu.Unlock()
		if len(got) == 0 || got[len(got)-1] != ConnectionStateClosed {
			t.Fatalf("terminal lifecycle sequence = %v, want a final closed event", got)
		}
		if len(got) == 2 && (got[0] != ConnectionStateReady || got[1] != ConnectionStateClosed) {
			t.Fatalf("lifecycle sequence = %v, want ready then closed or closed only", got)
		}
		if len(got) > 2 {
			t.Fatalf("lifecycle emitted more than one ready and one closed event: %v", got)
		}
	}
}

func TestConnectionLifecycleCloseStartSuppressesReady(t *testing.T) {
	var states []ConnectionState
	conn := &Conn{id: 42}
	conn.startLifecycleObserver(func(event ConnectionStateObservation) {
		states = append(states, event.State)
	})

	// Keep teardown pending after close begins, as Conn.close does while it
	// closes the negotiator, data channels, and transports.
	conn.beginConnectionClose()
	conn.emitConnectionReady()
	conn.emitConnectionClosed(nil)
	<-conn.lifecycleDone

	if len(states) != 1 || states[0] != ConnectionStateClosed {
		t.Fatalf("lifecycle sequence after close began = %v, want only closed", states)
	}
}

func TestTransportSnapshotDeliveryIsBoundedAndReportsDroppedUpdates(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	entered := make(chan struct{})
	release := make(chan struct{})
	blockNext := make(chan struct{}, 1)
	events := make(chan TransportSnapshotObservation, 256)
	var active, maxActive atomic.Int32
	_, _, conn := dialAcceptedListenerWithConfig(t, client, server, ListenConfig{
		AllowAnonymous: true,
		ObserveTransportSnapshot: func(event TransportSnapshotObservation) {
			current := active.Add(1)
			for previous := maxActive.Load(); current > previous && !maxActive.CompareAndSwap(previous, current); previous = maxActive.Load() {
			}
			defer active.Add(-1)
			select {
			case <-blockNext:
				close(entered)
				<-release
			default:
			}
			events <- event
		},
	})
	awaitSnapshotIdle(t, conn)
	drainSnapshotEvents(events)
	blockNext <- struct{}{}
	conn.emitTransportSnapshotAsync()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("blocking snapshot callback did not start")
	}
	for range 50 {
		conn.emitTransportSnapshotAsync()
	}
	if got := conn.droppedTransportSnapshots.Load(); got < 49 {
		t.Fatalf("dropped snapshot count = %d, want at least 49 coalesced updates", got)
	}
	close(release)
	select {
	case <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked snapshot callback did not finish")
	}
	awaitSnapshotIdle(t, conn)
	drainSnapshotEvents(events)
	conn.emitTransportSnapshotAsync()
	select {
	case event := <-events:
		if event.Snapshot.DroppedSnapshotEvents < 49 {
			t.Fatalf("snapshot reported %d dropped updates, want at least 49", event.Snapshot.DroppedSnapshotEvents)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot after coalescing was not delivered")
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("concurrent snapshot callbacks = %d, want at most 1", got)
	}
}

func awaitSnapshotIdle(t *testing.T, conn *Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn.snapshotMu.Lock()
		idle := !conn.snapshotPending && !conn.snapshotCallbackActive
		conn.snapshotMu.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("transport snapshot callback did not become idle")
}

func drainSnapshotEvents(events <-chan TransportSnapshotObservation) {
	for {
		select {
		case <-events:
		default:
			return
		}
	}
}

func TestDataChannelObservationReportsParseAndReassemblyFailures(t *testing.T) {
	var events []DataChannelMessageObservation
	conn := &Conn{
		id: 77,
		observeDataChannelMessage: func(event DataChannelMessageObservation) {
			events = append(events, event)
		},
	}
	channel := &dataChannel{
		conn:        conn,
		reliability: MessageReliabilityReliable,
		message:     &message{},
		packets:     make(chan []byte, 1),
		close:       make(chan struct{}),
	}

	event, err := channel.handleMessage([]byte{1}, false)
	if err == nil {
		t.Fatal("short segment did not fail parsing")
	}
	channel.observeMessage(event)
	if got := events[0]; got.ConnectionID != conn.id || got.ParseOutcome != MessageParseInvalid || got.ReassemblyOutcome != MessageReassemblyFailed || got.Err == nil {
		t.Fatal("invalid segment observation omitted its parse failure")
	}

	event, err = channel.handleMessage([]byte{2, 'a'}, false)
	if err != nil {
		t.Fatalf("first valid segment error = %v", err)
	}
	channel.observeMessage(event)
	event, err = channel.handleMessage([]byte{0, 'b'}, false)
	if err == nil {
		t.Fatal("out-of-sequence segment did not fail reassembly")
	}
	channel.observeMessage(event)
	got := events[2]
	if got.ConnectionID != conn.id || got.ParseOutcome != MessageParseValid || got.ReassemblyOutcome != MessageReassemblyFailed || got.SegmentCount != 3 || got.SegmentIndex != 1 || got.Err == nil {
		t.Fatal("reassembly failure observation omitted segment correlation")
	}
}
