package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"github.com/gofiber/fiber/v3"
)

var lock sync.Mutex
var server *socks5.Server
var listener net.Listener

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

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to create certificate directory: %w",
			err,
		)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"failed to generate RSA key: %w",
			err,
		)
	}

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

func RunSocks(c fiber.Ctx) error {
	lock.Lock()
	defer lock.Unlock()
	id := c.Params("id")

	rows, err := db.Query(`SELECT running FROM server`)
	if err != nil {
		return Respond(c, false, err.Error())
	}
	var runningList []int
	for rows.Next() {
		var running int
		if err := rows.Scan(&running); err != nil {
			rows.Close()
			return Respond(c, false, err.Error())
		}
		runningList = append(runningList, running)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Respond(c, false, err.Error())
	}
	for _, running := range runningList {
		if running != 0 {
			return Respond(c, false, "another server is already running")
		}
	}

	var host, username, encPassword string
	err = db.QueryRow(`SELECT host, username, password FROM server WHERE id = ?`, id).Scan(&host, &username, &encPassword)
	if err == sql.ErrNoRows {
		return Respond(c, false, "server not found")
	}
	if err != nil {
		return Respond(c, false, err.Error())
	}

	password, err := Decrypt(encPassword, serverSecret)
	if err != nil {
		return Respond(c, false, "failed to decrypt password: "+err.Error())
	}

	creds := socks5.StaticCredentials{username: password}
	auth := socks5.UserPassAuthenticator{Credentials: creds}

	config := &socks5.Config{
		AuthMethods: []socks5.Authenticator{auth},
		Logger:      log.New(io.Discard, "", 0),
	}
	server, err = socks5.New(config)

	if err != nil {
		return Respond(c, false, "failed to init socks: "+err.Error())
	}
	cert, err := generateSelfSignedCert(host)

	if err != nil {
		return Respond(c, false, "failed to generate cert: "+err.Error())
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	l, err := tls.Listen("tcp", ":4500", tlsConfig)
	listener = l

	server.Serve(l)

	return Respond(c, true, "")
}

func StopSocks(c fiber.Ctx) error {
	lock.Lock()
	defer lock.Unlock()

	if server == nil || listener == nil {
		return Respond(c, false, "server not started")
	}
	l := listener
	server = nil
	listener = nil

	if err := l.Close(); err != nil {
		return Respond(c, false, err.Error())
	}
	return Respond(c, true, "")
}
