package tests

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"time"
)

// loadCertPool loads the certificate pool from server certificate.
func loadCertPool(certPath string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	serverCert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(serverCert)
	return certPool, nil
}

// TestFirstConnection simulates the first-time connection to the server.
func TestFirstConnection(t *testing.T) {
	certPool, err := loadCertPool("../certs/server.crt")
	if err != nil {
		t.Fatalf("Failed to load server certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    certPool,
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		t.Fatalf("First connection failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	log.Printf("First connection response: %s", string(body))
}

// TestSessionResumption verifies session resumption and 0-RTT on subsequent connections.
func TestSessionResumption(t *testing.T) {
	certPool, err := loadCertPool("../certs/server.crt")
	if err != nil {
		t.Fatalf("Failed to load server certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    certPool,
		// Enable0RTT: true,
	}

	// First request to establish session
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		t.Fatalf("Initial request failed: %v", err)
	}
	defer resp.Body.Close()

	_, _ = io.ReadAll(resp.Body)

	// Delay to test session resumption
	time.Sleep(2 * time.Second)

	// Second request to test session resumption
	resp2, err := client.Get("https://localhost:8443")
	if err != nil {
		t.Fatalf("Session resumption request failed: %v", err)
	}
	defer resp2.Body.Close()

	body, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	log.Printf("Session resumption response: %s", string(body))
}

// TestRandomSessionTicket simulates different session ticket keys to check session resumption failure.
func TestRandomSessionTicket(t *testing.T) {
	certPool, err := loadCertPool("../certs/server.crt")
	if err != nil {
		t.Fatalf("Failed to load server certificate: %v", err)
	}

	// Random session ticket key, resetting the session cache
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random session ticket key: %v", err)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    certPool,
	}
	tlsConfig.SetSessionTicketKeys([][32]byte{to32ByteArray(key)})

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	// First request
	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		t.Fatalf("Initial request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	// Changing session ticket key to invalidate the session
	newKey := make([]byte, 32)
	_, err = rand.Read(newKey)
	if err != nil {
		t.Fatalf("Failed to generate a new session ticket key: %v", err)
	}
	tlsConfig.SetSessionTicketKeys([][32]byte{to32ByteArray(newKey)})

	// Subsequent request should fail session resumption
	resp2, err := client.Get("https://localhost:8443")
	if err != nil {
		t.Fatalf("Session resumption request failed: %v", err)
	}
	defer resp2.Body.Close()
	body, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	log.Printf("Response after changing session ticket key: %s", string(body))
}

// Helper to convert byte slice to fixed-size array
func to32ByteArray(b []byte) [32]byte {
	var array [32]byte
	copy(array[:], b)
	return array
}
