package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	certPool := x509.NewCertPool()
	serverCert, err := os.ReadFile("certs/server.crt")
	if err != nil {
		log.Fatalf("Unable to read server certificate: %v", err)
	}

	certPool.AppendCertsFromPEM(serverCert)

	// Configure TLS settings
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    certPool,
	}

	// Create an HTTP client with custom transport
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// First request
	sendRequest(client)

	// Subsequent requests to test session resumption
	sendRequest(client)
	sendRequest(client)
}

func sendRequest(client *http.Client) {
	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read and print the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	fmt.Println("Response from server:", string(body))
}
