package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/armon/go-socks5"
)

func generateSelfSignedCert(host string) (tls.Certificate, error) {

	const certDir = "./crt"
	const certPath = certDir + "/server.crt"
	const keyPath = certDir + "/server.key"

	if _, certErr := os.Stat(certPath); certErr == nil {
		if _, keyErr := os.Stat(keyPath); keyErr == nil {
			existingCert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil && len(existingCert.Certificate) > 0 {
				cert, err := x509.ParseCertificate(existingCert.Certificate[0])
				if err == nil && time.Now().Before(cert.NotAfter) {
					return existingCert, nil
				}
			}
		}
	}

	// 创建证书目录
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to create certificate directory: %w",
			err,
		)
	}

	// 生成 RSA 私钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to generate RSA key: %w",
			err,
		)
	}

	// 随机序列号
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to generate serial number: %w",
			err,
		)
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: serialNumber,

		Subject: pkix.Name{
			Organization: []string{"My Private Proxy"},
			CommonName:   host,
		},

		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(365 * 24 * time.Hour),

		// 关键：把 HOST 放进 SAN
		DNSNames: []string{host},

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to create certificate: %w",
			err,
		)
	}

	// 保存 server.crt
	certFile, err := os.OpenFile(
		certPath,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600,
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to create certificate file: %w",
			err,
		)
	}

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		certFile.Close()
		return tls.Certificate{}, fmt.Errorf(
			"failed to write certificate: %w",
			err,
		)
	}

	if err := certFile.Close(); err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to close certificate file: %w",
			err,
		)
	}

	// 保存 server.key
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to marshal private key: %w",
			err,
		)
	}

	keyFile, err := os.OpenFile(
		keyPath,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600,
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to create private key file: %w",
			err,
		)
	}

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		keyFile.Close()
		return tls.Certificate{}, fmt.Errorf(
			"failed to write private key: %w",
			err,
		)
	}

	if err := keyFile.Close(); err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to close private key file: %w",
			err,
		)
	}

	// 计算 SHA256 指纹
	sum := sha256.Sum256(derBytes)
	fingerprint := make([]string, len(sum))
	for i, b := range sum {
		fingerprint[i] = fmt.Sprintf("%02X", b)
	}

	fmt.Println("Generated TLS certificate:", certPath)
	fmt.Println("TLS private key:", keyPath)
	fmt.Println("SHA256 Fingerprint:", strings.Join(fingerprint, ":"))

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

func main() {
	username := os.Getenv("USERNAME")
	password := os.Getenv("PASSWORD")
	host := os.Getenv("HOST")
	port := "3000"
	if username == "" || password == "" {
		fmt.Println("USERNAME or PASSWORD is empty")
		return
	}
	if host == "" {
		fmt.Println("HOST is empty")
		return
	}
	creds := socks5.StaticCredentials{username: password}
	auth := socks5.UserPassAuthenticator{Credentials: creds}

	config := &socks5.Config{
		AuthMethods: []socks5.Authenticator{auth},
		Logger:      log.New(io.Discard, "", 0),
	}
	server, err := socks5.New(config)
	if err != nil {
		fmt.Println("Failed to create SOCKS5 server:", err.Error())
		return
	}
	cert, err := generateSelfSignedCert(host)
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
