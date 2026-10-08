package nethernet

import (
	"testing"

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
