package nethernet

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"

	"github.com/pion/webrtc/v4"
)

// MessageReliability represents the reliability of messages sent in a data channel.
// It is an internal type specific to this package's implementation, and shouldn't
// be sent over network in any way.
type MessageReliability uint8

const (
	// MessageReliabilityReliable guarantees the ordering of messages. Currently, this is the
	// only reliability parameter used in the game.
	MessageReliabilityReliable MessageReliability = iota
	// MessageReliabilityUnreliable seems to be unused, and it is unclear how it
	// works with multiple segments as packet drops could leave the message data
	// in unconstructed state.
	// While it is technically possible to send or receive packets in this channel,
	// it is currently recommended to use only MessageReliabilityReliable.
	MessageReliabilityUnreliable

	// messageReliabilityCapacity is the maximum value for MessageReliability, used as the capacity for array.
	messageReliabilityCapacity
)

// Parameters returns a [webrtc.DataChannelParameters], which may be used for creating a data channel for
// the MessageReliability or to ensure that a data channel is valid to handle it in the Conn.
func (r MessageReliability) Parameters() *webrtc.DataChannelParameters {
	switch r {
	case MessageReliabilityReliable:
		return &webrtc.DataChannelParameters{
			Label:   "ReliableDataChannel",
			Ordered: true,
		}
	case MessageReliabilityUnreliable:
		param := uint16(0)
		return &webrtc.DataChannelParameters{
			Label:          "UnreliableDataChannel",
			MaxRetransmits: &param,
		}
	default:
		panic(fmt.Sprintf("nethernet: MessageReliability.Parameters: unknown value: %d", r))
	}
}

// Valid determines whether the [webrtc.DataChannel] can be safe to use in Conn.
// If the data channel does not have the exact same parameters returned by [MessageReliability.Parameters],
// it will return false.
func (r MessageReliability) Valid(channel *webrtc.DataChannel) bool {
	params := r.Parameters()
	// Compare non-pointer values
	if channel.Label() != params.Label ||
		channel.Protocol() != params.Protocol ||
		channel.Ordered() != params.Ordered ||
		channel.Negotiated() != params.Negotiated {
		return false
	}
	// Compare pointer values that should be compared deeply with the underlying values
	return r.compareOptional(channel.MaxPacketLifeTime(), params.MaxPacketLifeTime) &&
		r.compareOptional(channel.MaxRetransmits(), params.MaxRetransmits)
}

// compareOptional returns true if both optional uint16 values are equal.
// It evaluates two nil *uint16s as equal, and if both pointers are non nil,
// it compares the underlying uint16 values. If one is nil and the other is not,
// it returns false.
func (r MessageReliability) compareOptional(a, b *uint16) bool {
	if a != nil && b != nil {
		return *a == *b
	}
	return a == nil && b == nil
}

// wrapDataChannel wraps a [webrtc.DataChannel] and sets up handlers to reconstruct
// fragmented messages. Received message segments are reassembled and sent to packets
// when all segments have arrived.
func wrapDataChannel(channel *webrtc.DataChannel, reliability MessageReliability, conn *Conn) *dataChannel {
	ch := &dataChannel{
		DataChannel: channel,
		conn:        conn,
		reliability: reliability,
		// Previously, message.data was pre-allocated for all possible segments.
		// Since most messages are smaller than 256KB and don't require fragmentation,
		// we no longer need to pre-allocate a large buffer.
		message: &message{},
		packets: make(chan []byte),
		close:   make(chan struct{}),
	}
	ch.OnMessage(func(msg webrtc.DataChannelMessage) {
		event, err := ch.handleMessage(msg.Data, msg.IsString)
		ch.observeMessage(event)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				conn.log.Debug("message dropped due to closure of data channel",
					slog.String("label", ch.Label()))
				return
			}
			// Receiving an invalid or incomplete message is considered unrecoverable
			// as segmented packets cannot be completed. Closing the connection also
			// helps mitigate malformed or malicious input from a peer.
			// The DataChannel invokes this callback while holding an internal lock,
			// so the connection is closed in a goroutine to avoid deadlock.
			go conn.close(fmt.Errorf("nethernet: handle message in %s: %w", ch.Label(), err))
		}
	})
	ch.OnClose(func() {
		// This handler function itself is invoked while holding an internal lock, so call close in a goroutine to avoid deadlock.
		go conn.close(fmt.Errorf("nethernet: data channel %q closed by remote peer", ch.Label()))
	})
	return ch
}

// dataChannel represents the data channel responsible for sending and receiving messages in MessageReliability
// within a Conn. It contains the fields necessary for handling multiple segments received in the embedded [webrtc.DataChannel].
type dataChannel struct {
	*webrtc.DataChannel
	conn *Conn

	// An embedded message contains the buffer that holds the segments received
	// to now and the count of the last segment count.
	*message
	// messageMu guards message because Pion may invoke OnMessage concurrently
	// with Conn/data channel closure.
	messageMu sync.Mutex

	// reliability is the reliability parameter for dataChannel.
	// It controls how multiple segments received in the data channel is handled.
	reliability MessageReliability

	// When writing multiple segments to the dataChannel, it should be locked using
	// its embedded [sync.Mutex] for guaranteeing ordered segment counts.
	write sync.Mutex

	// packets can be used to receive packets that are fully-reconstructed from
	// one or more segments received in the dataChannel.
	packets chan []byte

	// close is a channel that is closed when a dataChannel is closed.
	close chan struct{}
	// once ensures the dataChannel is closed only once.
	once sync.Once
}

// message represents the structure of remote messages sent in ReliableDataChannel.
type message struct {
	// segments represents the number of segments the message is split into.
	segments uint8
	// totalSegments is set from the first segment and used to report message-relative indices.
	totalSegments int
	// receivedSegments counts accepted segments for the current message.
	receivedSegments int
	// data represents the payload of the message.
	data []byte
}

// parseMessage parses the provided data into a message. The first byte indicates the count of segments,
// and the remaining bytes are its payload. If the data is less than 2 bytes, an error is returned.
func parseMessage(b []byte) (*message, error) {
	if len(b) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	return &message{
		segments: b[0],
		data:     b[1:],
	}, nil
}

// handleMessage handles a message received from a [webrtc.DataChannel] for the reliability. It parses
// the incoming data into a message using parseMessage and handles the segments, and if all segments has
// been received, it sends the buffer to either [Conn.Read] or [Conn.ReadPacket].
func (c *dataChannel) handleMessage(b []byte, isString bool) (DataChannelMessageObservation, error) {
	var event DataChannelMessageObservation
	observing := c.conn != nil && c.conn.observeDataChannelMessage != nil
	if observing {
		event = c.observation(DataChannelMessageInbound, isString)
		// The observer copies Pion's callback-owned buffer once immediately
		// before invoking user code.
		event.Data = b
		event.ParseOutcome = MessageParseNotAttempted
		event.ReassemblyOutcome = MessageReassemblyNotApplicable
	}
	select {
	case <-c.close:
		if observing {
			event.Err = net.ErrClosed
		}
		return event, net.ErrClosed
	default:
	}

	msg, err := parseMessage(b)
	if err != nil {
		err = fmt.Errorf("parse: %w", err)
		if observing {
			event.ParseOutcome = MessageParseInvalid
			event.ReassemblyOutcome = MessageReassemblyFailed
			event.Err = err
		}
		return event, err
	}
	if observing {
		event.ParseOutcome = MessageParseValid
		event.SegmentCount = int(msg.segments) + 1
		event.SegmentIndex = 0
		event.ReassemblyOutcome = MessageReassemblyPending
	}

	if c.reliability == MessageReliabilityUnreliable && msg.segments > 0 {
		err = fmt.Errorf("unexpected segment count on UnreliableDataChannel: %d", msg.segments)
		if observing {
			event.ReassemblyOutcome = MessageReassemblyFailed
			event.Err = err
		}
		return event, err
	}

	c.messageMu.Lock()
	if c.segments > 0 && c.segments-1 != msg.segments {
		err = fmt.Errorf("invalid promised segments: expected %d, got %d", c.segments-1, msg.segments)
		if observing {
			event.SegmentCount = c.totalSegments
			event.SegmentIndex = c.receivedSegments
			event.ReassemblyOutcome = MessageReassemblyFailed
			event.Err = err
		}
		c.messageMu.Unlock()
		return event, err
	}

	if c.receivedSegments == 0 {
		c.totalSegments = int(msg.segments) + 1
	}
	if observing {
		event.SegmentCount = c.totalSegments
		event.SegmentIndex = c.receivedSegments
	}
	c.segments = msg.segments
	c.data = append(c.data, msg.data...)
	c.receivedSegments++

	if c.segments > 0 {
		c.messageMu.Unlock()
		return event, nil
	}
	if observing {
		event.ReassemblyOutcome = MessageReassemblyComplete
		// c.data is handed to the packet receiver below, so the observation
		// needs its own one-time copy before that ownership transfer.
		event.ReassembledData = slices.Clone(c.data)
	}
	c.totalSegments = 0
	c.receivedSegments = 0

	select {
	case <-c.close:
		err = net.ErrClosed
	case c.packets <- c.data:
		c.data = nil
	}
	c.messageMu.Unlock()
	if err != nil {
		if observing {
			event.Err = err
		}
	}

	return event, err
}

func (c *dataChannel) observation(direction DataChannelMessageDirection, isString bool) DataChannelMessageObservation {
	event := DataChannelMessageObservation{
		Direction:         direction,
		Reliability:       c.reliability,
		IsString:          isString,
		ReassemblyOutcome: MessageReassemblyNotApplicable,
	}
	if c.conn != nil {
		event.ConnectionID = c.conn.id
	}
	if c.DataChannel != nil {
		event.Label = c.Label()
		event.Protocol = c.Protocol()
		event.Ordered = c.Ordered()
		event.Negotiated = c.Negotiated()
		event.BufferedAmount = c.BufferedAmount()
		if streamID := c.ID(); streamID != nil {
			event.StreamID = *streamID
			event.HasStreamID = true
		}
		event.MaxRetransmits = c.MaxRetransmits()
		event.MaxPacketLifeTime = c.MaxPacketLifeTime()
	}
	return event
}

func (c *dataChannel) observeMessage(event DataChannelMessageObservation) {
	if c.conn == nil {
		return
	}
	if observe := c.conn.observeDataChannelMessage; observe != nil {
		// Pion owns the OnMessage buffer. Clone it before handing the event to user code.
		event.Data = slices.Clone(event.Data)
		event.MaxRetransmits = cloneUint16(event.MaxRetransmits)
		event.MaxPacketLifeTime = cloneUint16(event.MaxPacketLifeTime)
		observe(event)
	}
}

func cloneUint16(value *uint16) *uint16 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

// Close closes the underlying [webrtc.DataChannel].
func (c *dataChannel) Close() (err error) {
	c.once.Do(func() {
		close(c.close)
		c.messageMu.Lock()
		clear(c.data)
		c.messageMu.Unlock()
		err = c.DataChannel.Close()
	})
	return err
}
