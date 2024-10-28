package main

import (
	"crypto/rand"
	"crypto/tls"
	"log"
	"net/http"
)

func main() {
	cert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
	if err != nil {
		log.Fatalf("Failed to load server certificate and key: %v", err)
	}

	// Generate custom session ticket keys using go's crypto library
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	if _, err := rand.Read(key1); err != nil {
		log.Fatalf("Failed to generate session ticket key1: %v", err)
	}
	if _, err := rand.Read(key2); err != nil {
		log.Fatalf("Failed to generate session ticket key2: %v", err)
	}

	// TlS configuration
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		//Enable0RTT:   true, // Enable 0-RTT support
	}

	//session key setup
	tlsConfig.SetSessionTicketKeys([][32]byte{to32ByteArray(key1), to32ByteArray(key2)})

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, secure world with custom session ticket keys!"))
		}),
	}

	log.Println("Starting server on https://localhost:8443")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func to32ByteArray(b []byte) [32]byte {
	var array [32]byte
	copy(array[:], b)
	return array
}
