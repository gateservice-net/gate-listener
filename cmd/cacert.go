// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build ignore

// Usage: go run cacert.go
//
// This tool generates a consistent, dummy root certificate for proxy client
// certificates.  It isn't relied on for security.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

func main() {
	// Secret key consists of all zeros on purpose.  It's not really secret.
	_, key, err := ed25519.GenerateKey(zeroer{})
	if err != nil {
		panic(err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}

	pem.Encode(os.Stdout, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Unix(1000000000, 0),  // Year 2001.
		NotAfter:              time.Unix(10000000000, 0), // Year 2286.
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Avoid randomness on purpose.
	cert, err := x509.CreateCertificate(zeroer{}, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}

	pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
}

type zeroer struct{}

func (zeroer) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}
