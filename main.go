package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/armon/go-socks5"
)

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"My Private Proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

func main() {
	username := os.Getenv("USERNAME")
	password := os.Getenv("PASSWORD")
	port := "3000"
	if username == "" || password == "" {
		fmt.Println("USERNAME or PASSWORD is empty")
		return
	}
	creds := socks5.StaticCredentials{username: password}
	auth := socks5.UserPassAuthenticator{Credentials: creds}

	config := &socks5.Config{
		AuthMethods: []socks5.Authenticator{auth},
	}
	server, err := socks5.New(config)
	if err != nil {
		fmt.Println("Failed to create SOCKS5 server:", err.Error())
		return
	}
	cert, err := generateSelfSignedCert()
	if err != nil {
		fmt.Println("Failed to generate cert:", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	addr := ":" + port
	l, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		fmt.Println("Listen error:", err.Error())
		return
	}

	fmt.Println("Secure SOCKS5 over TLS server running on port", port)
	server.Serve(l)
}
