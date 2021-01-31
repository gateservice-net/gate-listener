// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package proxy can be used with the Gate service savo.la/gate/listener when
// it doesn't allow public client connections.  The proxy creates client
// certificates using the Ed25519 private key which owns the Gate instance.
package proxy

import (
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/tsavola/mu"
)

// Proxy manages client certificates automatically.
type Proxy struct {
	key ed25519.PrivateKey

	mu      mu.Mutex
	pending chan struct{}
	certs   []tls.Certificate // 0 to 1 certificates.
	err     error
}

// New supports ed25519.PrivateKey.
func New(key crypto.PrivateKey) *Proxy {
	return &Proxy{
		key: key.(ed25519.PrivateKey),
	}
}

// Dial with default dialer.  See DialWithDialer for details.
func (p *Proxy) Dial(network, addr string, config *tls.Config) (*tls.Conn, error) {
	return p.DialWithDialer(new(net.Dialer), network, addr, config)
}

// DialWithDialer and transparent connection authentication.  Either addr or
// config.ServerName should refer to the DNS name of a Gate listener endpoint.
// ServerName is set automatically if it's empty.
func (p *Proxy) DialWithDialer(dialer *net.Dialer, network, addr string, config *tls.Config) (*tls.Conn, error) {
	certs, err := p.getCert()
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(tls.Config)
	} else {
		config = config.Clone()
	}

	if config.ServerName == "" {
		config.ServerName, _, err = net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
	}

	if len(config.Certificates) == 0 {
		config.Certificates = certs
	} else {
		config.Certificates = append(append([]tls.Certificate{}, certs...), config.Certificates...)
	}

	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS13
	}

	return tls.DialWithDialer(dialer, network, addr, config)
}

func (p *Proxy) getCert() ([]tls.Certificate, error) {
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

retry:
	if p.err != nil {
		return nil, p.err
	}

	if len(p.certs) == 0 {
		p.certs, p.err = newCert(p.key)
	} else if p.certs[0].Leaf.NotAfter.Before(now.Add(5 * time.Minute)) {
		if p.pending == nil {
			p.pending = make(chan struct{})
			go p.replaceCert()
		} else if p.certs[0].Leaf.NotAfter.Before(now.Add(4 * time.Minute)) {
			wait := p.pending
			p.mu.UnlockGuard(func() {
				<-wait
				now = time.Now()
			})
			goto retry
		}
	}

	return p.certs, p.err
}

func (p *Proxy) replaceCert() {
	var (
		certs []tls.Certificate
		err   error
	)

	defer p.mu.Guard(func() {
		close(p.pending)
		p.pending = nil
		p.certs = certs
		p.err = err
	})

	certs, err = newCert(p.key)
}

func newCert(key ed25519.PrivateKey) ([]tls.Certificate, error) {
	c, err := CreateClientCertificate(key, time.Now(), nil)
	if err != nil {
		return nil, err
	}

	return []tls.Certificate{c}, nil
}

// CreateClientCertificate valid for a short time.  Supports
// ed25519.PrivateKey.
func CreateClientCertificate(key crypto.PrivateKey, now time.Time, rand io.Reader) (tls.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	data, err := x509.CreateCertificate(rand, template, rootCert, key.(ed25519.PrivateKey).Public(), rootKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certx, err := x509.ParseCertificate(data)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{data},
		PrivateKey:  key,
		Leaf:        certx,
	}
	return cert, nil
}
