// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
)

// rootKeyPEM and rootCertPEM were generated using cmd/cacert.go

var rootKeyPEM = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PRIVATE KEY-----
`

var rootCertPEM = `
-----BEGIN CERTIFICATE-----
MIHyMIGloAMCAQICAQEwBQYDK2VwMAAwIBcNMDEwOTA5MDE0NjQwWhgPMjI4NjEx
MjAxNzQ2NDBaMAAwKjAFBgMrZXADIQA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6
wEihi1naKaNCMEAwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFIwwyX5/1UYM47li20zXWHnuzYq9MAUGAytlcANBABq6e9bvBpL8woZ1
UbJcDugz6wOJBbUMxPpFfIywQK+5fXch5cJ1ToueuiR/j26qTuxu0VPdhelnItFz
oxDgjQs=
-----END CERTIFICATE-----
`

var (
	rootKey  crypto.PrivateKey
	rootCert *x509.Certificate
)

func init() {
	b, _ := pem.Decode([]byte(rootKeyPEM))
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		panic(err)
	}

	b, _ = pem.Decode([]byte(rootCertPEM))
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}

	rootKey = key
	rootCert = cert
}
