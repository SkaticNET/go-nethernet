package endpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
)

func TestClientSignalDeliversSDPAnswer(t *testing.T) {
	const answer = "v=0\r\ns=-\r\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodPost)
		}
		if r.URL.Path != "/v1/join/123" {
			t.Fatalf("path = %s, want /v1/join/123", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(answer))
	}))
	defer server.Close()

	client := ClientConfig{NetworkID: "123"}.New()
	signals := make(chan *nethernet.Signal, 1)
	stop := client.Notify(notifierFunc(func(signal *nethernet.Signal) {
		signals <- signal
	}))
	defer stop()

	if err := client.Signal(context.Background(), &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 42,
		NetworkID:    server.URL,
		Data:         "offer",
	}); err != nil {
		t.Fatalf("Signal() error = %v", err)
	}

	select {
	case signal := <-signals:
		if signal.Type != nethernet.SignalTypeAnswer {
			t.Fatalf("signal type = %q, want %q", signal.Type, nethernet.SignalTypeAnswer)
		}
		if signal.ConnectionID != 42 {
			t.Fatalf("connection ID = %d, want 42", signal.ConnectionID)
		}
		if signal.NetworkID != server.URL {
			t.Fatalf("network ID = %q, want %q", signal.NetworkID, server.URL)
		}
		if signal.Data != answer {
			t.Fatalf("data = %q, want %q", signal.Data, answer)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for signal")
	}
}

func TestClientSignalRejectsOversizedSDPAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, strings.NewReader(strings.Repeat("x", int(maxSDPBodySize)+1)))
	}))
	defer server.Close()

	client := NewClient()

	err := client.Signal(context.Background(), &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 42,
		NetworkID:    server.URL,
		Data:         "offer",
	})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("exceeds %d bytes", maxSDPBodySize)) {
		t.Fatalf("Signal() error = %v, want SDP size error", err)
	}
}

func TestHandlerServesSDPAnswer(t *testing.T) {
	const answer = "v=0\r\ns=-\r\n"
	handler := newTestHandler()
	stop := handler.Notify(notifierFunc(func(signal *nethernet.Signal) {
		go func() {
			_ = handler.Signal(context.Background(), &nethernet.Signal{
				Type:         nethernet.SignalTypeAnswer,
				ConnectionID: signal.ConnectionID,
				NetworkID:    signal.NetworkID,
				Data:         answer,
			})
		}()
	}))
	defer stop()

	req := httptest.NewRequest(http.MethodPost, "/v1/join/123", strings.NewReader("offer"))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	result := recorder.Result()
	defer result.Body.Close()

	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusOK)
	}
	if got := result.Header.Get("Content-Type"); got != "application/sdp" {
		t.Fatalf("content type = %q, want application/sdp", got)
	}
}

func TestHandlerCaptureKeepsOrdinaryResponseHeadersOutOfTrailers(t *testing.T) {
	classified := responseTrailers(http.Header{
		"Trailer":                         {"X-Declared"},
		"X-Declared":                      {"declared-value"},
		http.TrailerPrefix + "X-Prefixed": {"prefixed-value"},
		"Content-Type":                    {"text/plain"},
		"X-Ordinary":                      {"ordinary-value"},
	})
	if len(classified) != 2 || classified.Get("X-Declared") != "declared-value" || classified.Get("X-Prefixed") != "prefixed-value" {
		t.Fatalf("responseTrailers() = %#v, want only declared and prefixed trailer fields", classified)
	}
	var events []nethernet.CaptureEvent
	handler := (HandlerConfig{CaptureRequest: func(*http.Request) (*nethernet.Capture, error) {
		return &nethernet.Capture{Event: func(event nethernet.CaptureEvent) error {
			events = append(events, event)
			return nil
		}}, nil
	}}).New()
	handler.Status(Status{ServerName: "synthetic"})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/join", nil))
	var complete *nethernet.CaptureEvent
	for i := range events {
		if events[i].Kind == "http-response-complete" {
			complete = &events[i]
		}
	}
	if complete == nil {
		t.Fatal("missing terminal response event")
	}
	if complete.Headers.Get("Content-Type") == "" {
		t.Fatalf("ordinary response header missing: %#v", complete.Headers)
	}
	if len(complete.Trailers) != 0 {
		t.Fatalf("ordinary response headers were mislabeled as trailers: %#v", complete.Trailers)
	}
}

func TestHandlerAbortsSuccessfulResponseWhenHeaderCaptureFails(t *testing.T) {
	captureErr := errors.New("controlled header capture failure")
	var failureReported bool
	capture := &nethernet.Capture{
		Event: func(event nethernet.CaptureEvent) error {
			if event.Kind == "http-response" {
				return captureErr
			}
			return nil
		},
	}
	capture.SetFailureHandler(func(err error) { failureReported = errors.Is(err, captureErr) })
	handler := (HandlerConfig{CaptureRequest: func(*http.Request) (*nethernet.Capture, error) {
		return capture, nil
	}}).New()
	handler.Status(Status{ServerName: "must-not-be-served"})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/join", nil))
	result := recorder.Result()
	defer result.Body.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode == http.StatusOK || strings.Contains(string(body), "must-not-be-served") {
		t.Fatalf("capture failure still served successful response: status=%d body=%q", result.StatusCode, body)
	}
	if !failureReported {
		t.Fatal("capture failure handler was not called")
	}
}

func TestHandlerAbortsRequestWhenInitialCaptureFails(t *testing.T) {
	for _, test := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "discovery GET", method: http.MethodGet, path: "/v1/join"},
		{name: "offer POST", method: http.MethodPost, path: "/v1/join/123", body: "offer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			captureErr := errors.New("controlled initial capture failure")
			var failureReported bool
			capture := &nethernet.Capture{Event: func(event nethernet.CaptureEvent) error {
				if event.Kind == "http-request" {
					return captureErr
				}
				return nil
			}}
			capture.SetFailureHandler(func(err error) { failureReported = errors.Is(err, captureErr) })
			handler := (HandlerConfig{CaptureRequest: func(*http.Request) (*nethernet.Capture, error) {
				return capture, nil
			}}).New()
			handler.disableNotifyTypeCheck = true
			handler.Status(Status{ServerName: "must-not-be-served"})
			var offers atomic.Int32
			stop := handler.Notify(notifierFunc(func(signal *nethernet.Signal) {
				if signal.Type == nethernet.SignalTypeOffer {
					offers.Add(1)
				}
			}))
			defer stop()
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, strings.NewReader(test.body)))
			result := recorder.Result()
			defer result.Body.Close()
			response, err := io.ReadAll(result.Body)
			if err != nil {
				t.Fatal(err)
			}
			if result.StatusCode == http.StatusOK || strings.Contains(string(response), "must-not-be-served") {
				t.Fatalf("capture failure returned successful response: status=%d body=%q", result.StatusCode, response)
			}
			if !failureReported {
				t.Fatal("initial capture failure was not reported")
			}
			if got := offers.Load(); got != 0 {
				t.Fatalf("offer notifications = %d, want zero", got)
			}
		})
	}
}

func TestServeTLSCloseCancelsContextWithoutServerClosedCause(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	handler, err := HandlerConfig{}.ServeTLS("127.0.0.1:0", certFile, keyFile)
	if err != nil {
		t.Fatalf("ServeTLS() error = %v", err)
	}

	if err := handler.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-handler.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for handler context cancellation")
	}
	if err := context.Cause(handler.Context()); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("context cause = %v, want http.ErrServerClosed", err)
	}
}

func TestHandlerRejectsOversizedSDPOffer(t *testing.T) {
	handler := NewHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/join/123", strings.NewReader(strings.Repeat("x", int(maxSDPBodySize)+1)))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	result := recorder.Result()
	defer result.Body.Close()

	if result.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func newTestHandler() *Handler {
	handler := NewHandler()
	handler.disableNotifyTypeCheck = true
	return handler
}

func writeTestCertificate(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(cryptorand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

func TestHandlerReturnsServiceUnavailableWhenOfferNotAdmitted(t *testing.T) {
	handler := newTestHandler()
	stop := handler.Notify(rejectingNotifier{})
	defer stop()

	req := httptest.NewRequest(http.MethodPost, "/v1/join/123", strings.NewReader("offer"))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	result := recorder.Result()
	defer result.Body.Close()

	if result.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusServiceUnavailable)
	}
}

type notifierFunc func(*nethernet.Signal)

func (f notifierFunc) NotifySignal(signal *nethernet.Signal) bool {
	f(signal)
	return true
}

type rejectingNotifier struct{}

func (rejectingNotifier) NotifySignal(*nethernet.Signal) bool {
	return false
}
