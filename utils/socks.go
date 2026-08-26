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
var runningID string

var certMu sync.Mutex
var cachedCert *tls.Certificate
var cachedCertHost string
var cachedCertNotAfter time.Time

const certDir = "./crt"
const certPath = certDir + "/server.crt"
const keyPath = certDir + "/server.key"

const certRenewBefore = 30 * 24 * time.Hour
const certCheckInterval = 1 * time.Hour

var renewalStop chan struct{}

func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func generateSelfSignedCert(host string) (tls.Certificate, error) {

	if _, certErr := os.Stat(certPath); certErr == nil {
		if _, keyErr := os.Stat(keyPath); keyErr == nil {
			existingCert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil && len(existingCert.Certificate) > 0 {
				cert, err := x509.ParseCertificate(existingCert.Certificate[0])
				if err == nil && time.Now().Before(cert.NotAfter) && cert.Subject.CommonName == host {
					return existingCert, nil
				}
			}
		}
	}

	return createNewCert(host)
}

func createNewCert(host string) (tls.Certificate, error) {
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

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

func getOrRenewCert(host string) (*tls.Certificate, error) {
	certMu.Lock()
	defer certMu.Unlock()

	if cachedCert != nil && cachedCertHost == host && time.Now().Before(cachedCertNotAfter) {
		return cachedCert, nil
	}

	cert, err := generateSelfSignedCert(host)
	if err != nil {
		return nil, err
	}

	notAfter := time.Now().Add(365 * 24 * time.Hour)
	if len(cert.Certificate) > 0 {
		if parsed, parseErr := x509.ParseCertificate(cert.Certificate[0]); parseErr == nil {
			notAfter = parsed.NotAfter
		}
	}

	cachedCert = &cert
	cachedCertHost = host
	cachedCertNotAfter = notAfter

	return cachedCert, nil
}

func certRemainingSeconds() (int64, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return 0, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return 0, fmt.Errorf("invalid certificate file")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return int64(time.Until(cert.NotAfter).Seconds()), nil
}

func renewCertNow(host, id string) error {
	cert, err := createNewCert(host)
	if err != nil {
		return fmt.Errorf("failed to renew certificate: %w", err)
	}

	notAfter := time.Now().Add(365 * 24 * time.Hour)
	if len(cert.Certificate) > 0 {
		if parsed, parseErr := x509.ParseCertificate(cert.Certificate[0]); parseErr == nil {
			notAfter = parsed.NotAfter
		}
	}

	certMu.Lock()
	cachedCert = &cert
	cachedCertHost = host
	cachedCertNotAfter = notAfter
	certMu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	if runningID != id {
		return nil
	}

	now := time.Now().Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE config SET crt_created = ? WHERE running = ?`, now, id); err != nil {
		return fmt.Errorf("failed to update crt_created: %w", err)
	}

	return nil
}

func runCertRenewalLoop(host, id string, stop <-chan struct{}) {
	ticker := time.NewTicker(certCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			remaining, err := certRemainingSeconds()
			if err != nil {
				log.Printf("cert renewal check failed: %v\n", err)
				continue
			}

			if time.Duration(remaining)*time.Second > certRenewBefore {
				continue
			}

			if err := renewCertNow(host, id); err != nil {
				log.Printf("cert renewal failed: %v\n", err)
				continue
			}

			log.Printf("certificate auto-renewed for host %s\n", host)
		}
	}
}

func startSocksByID(id string) error {
	var host, username, encPassword string
	err := db.QueryRow(`SELECT host, username, password FROM server WHERE id = ?`, id).Scan(&host, &username, &encPassword)
	if err == sql.ErrNoRows {
		return fmt.Errorf("server not found")
	}
	if err != nil {
		return err
	}

	password, err := Decrypt(encPassword, serverSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt password: %w", err)
	}

	creds := socks5.StaticCredentials{username: password}
	auth := socks5.UserPassAuthenticator{Credentials: creds}

	config := &socks5.Config{
		AuthMethods: []socks5.Authenticator{auth},
		Logger:      log.New(io.Discard, "", 0),
	}
	srv, err := socks5.New(config)
	if err != nil {
		return fmt.Errorf("failed to init socks: %w", err)
	}

	if _, err := generateSelfSignedCert(host); err != nil {
		return fmt.Errorf("failed to generate cert: %w", err)
	}
	tlsConfig := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return getOrRenewCert(host)
		},
	}

	l, err := tls.Listen("tcp", ":4500", tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	now := time.Now().Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE config SET running = ?, crt_created = ?`, id, now); err != nil {
		l.Close()
		return fmt.Errorf("failed to update running state: %w", err)
	}

	server = srv
	listener = l
	runningID = id

	stop := make(chan struct{})
	renewalStop = stop
	go runCertRenewalLoop(host, id, stop)

	go func() {
		srv.Serve(l)
	}()

	return nil
}

func RunSocks(c fiber.Ctx) error {
	lock.Lock()
	defer lock.Unlock()
	id := c.Params("id")

	var currentRunning string
	err := db.QueryRow(`SELECT running FROM config`).Scan(&currentRunning)
	if err != nil {
		return Respond(c, false, err.Error())
	}
	if currentRunning != "" {
		return Respond(c, false, "another server is already running")
	}

	if err := startSocksByID(id); err != nil {
		return Respond(c, false, err.Error())
	}

	return Respond(c, true, "")
}

func AutoStartRunning() {
	lock.Lock()
	defer lock.Unlock()

	var id string
	err := db.QueryRow(`SELECT running FROM config`).Scan(&id)
	if err != nil || id == "" {
		return
	}

	if err := startSocksByID(id); err != nil {
		log.Printf("auto-start socks5 failed: %v\n", err)
		if _, resetErr := db.Exec(`UPDATE config SET running = '', crt_created = '' WHERE running = ?`, id); resetErr != nil {
			log.Printf("failed to reset running state after auto-start failure: %v\n", resetErr)
		}
	} else {
		log.Printf("auto-start socks5 server: %s\n", id)
	}
}

func StopSocks(c fiber.Ctx) error {
	lock.Lock()
	defer lock.Unlock()

	if server == nil || listener == nil {
		return Respond(c, false, "server not started")
	}
	l := listener

	if err := l.Close(); err != nil {
		return Respond(c, false, err.Error())
	}

	if renewalStop != nil {
		close(renewalStop)
		renewalStop = nil
	}

	if _, err := db.Exec(`UPDATE config SET running = '', crt_created = ''`); err != nil {
		server = nil
		listener = nil
		runningID = ""
		return Respond(c, false, "server stopped but failed to update running state: "+err.Error())
	}

	server = nil
	listener = nil
	runningID = ""
	return Respond(c, true, "")
}

func DownloadCert(c fiber.Ctx) error {
	certMu.Lock()
	defer certMu.Unlock()

	info, err := os.Stat(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Respond(c, false, "certificate not found")
		}
		return Respond(c, false, err.Error())
	}
	if info.IsDir() {
		return Respond(c, false, "certificate not found")
	}

	return c.Download(certPath, "server.crt")
}

func GetCertRemaining(c fiber.Ctx) error {
	certMu.Lock()
	defer certMu.Unlock()

	remaining, err := certRemainingSeconds()
	if err != nil {
		if os.IsNotExist(err) {
			return Respond(c, false, "certificate not found")
		}
		return Respond(c, false, err.Error())
	}

	return Respond(c, true, remaining)
}

func GetCertFingerprint(c fiber.Ctx) error {
	certMu.Lock()
	defer certMu.Unlock()

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Respond(c, false, "certificate not found")
		}
		return Respond(c, false, err.Error())
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return Respond(c, false, "invalid certificate file")
	}

	return Respond(c, true, certFingerprint(block.Bytes))
}
