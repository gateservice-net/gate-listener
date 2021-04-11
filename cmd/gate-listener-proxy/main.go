// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strings"

	"gateservice.net/listener/proxy"
	"golang.org/x/crypto/ssh"
)

type portDesc struct {
	name       string
	localAddr  string
	remotePort string
}

func main() {
	if err := Main(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func Main() error {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] remotehost\n", os.Args[0])
		flag.PrintDefaults()
	}

	var identityFile string
	if home := os.Getenv("HOME"); home != "" {
		identityFile = path.Join(home, ".ssh/id_ed25519")
	}
	flag.StringVar(&identityFile, "i", identityFile, "ssh-ed25519 private key for remote connections")

	var (
		localCert string
		localKey  string
	)
	flag.StringVar(&localCert, "tls-cert", localCert, "Local certificate; TLS enabled for all listeners")
	flag.StringVar(&localKey, "tls-key", localKey, "Local private key; TLS enabled for all listeners")

	ports := []portDesc{
		{"HTTP", "", "443"},
		{"SMTP", "", "465"},
		{"NNTP", "", "563"},
		{"LDAP", "", "636"},
		{"DNS", "", "853"},
		{"FTP data", "", "989"},
		{"FTP control", "", "990"},
		{"Telnet", "", "992"},
		{"IMAP", "", "993"},
		{"POP3", "", "995"},
		{"", "", "1111"},
		{"Gemini", "", "1965"},
		{"UUCP", "", "4031"},
		{"SIP", "", "5061"},
		{"XMPP client", "", "5223"},
		{"STUN/TURN", "", "5349"},
		{"AMQP", "", "5671"},
		{"NETCONF", "", "6513"},
		{"Syslog", "", "6514"},
		{"IRC", "", "6697"},
		{"MQTT", "", "8883"},
	}

	for i, p := range ports {
		name := p.name
		key := strings.ToLower(strings.Replace(strings.Replace(name, "/", "-", -1), " ", "-", -1))

		if name == "" {
			name = "custom protocol"
			key = p.remotePort
		}

		flag.StringVar(&ports[i].localAddr, key, p.localAddr, fmt.Sprintf("Local %s listening port or address, forwarded to remote TLS port %s", name, p.remotePort))
	}

	flag.Parse()
	if identityFile == "" || flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	remoteHost := flag.Arg(0)

	data, err := ioutil.ReadFile(identityFile)
	if err != nil {
		return err
	}

	x, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return err
	}

	authKey, ok := x.(*ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("%s: not an ed25519 private key", identityFile)
	}

	var localTLS *tls.Config

	if localCert != "" || localKey != "" {
		cert, err := tls.LoadX509KeyPair(localCert, localKey)
		if err != nil {
			return err
		}

		localTLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	prox := proxy.New(*authKey)
	done := make(chan error)

	for _, p := range ports {
		if p.localAddr != "" {
			localAddr := p.localAddr
			if !strings.Contains(":", localAddr) {
				localAddr = "localhost:" + localAddr
			}
			go forward(done, localAddr, localTLS, remoteHost+":"+p.remotePort, prox)
		}
	}

	return <-done
}

func forward(done chan<- error, localAddr string, localTLS *tls.Config, remoteAddr string, prox *proxy.Proxy) {
	var err error
	defer func() {
		if err == nil {
			err = errors.New("panic")
		}
		done <- fmt.Errorf("%s: %v", localAddr, err)
	}()

	l, err := net.Listen("tcp", localAddr)
	if err != nil {
		return
	}
	defer l.Close()

	for {
		var conn net.Conn

		conn, err = l.Accept()
		if err != nil {
			return
		}

		go handle(conn.(*net.TCPConn), localTLS, remoteAddr, prox)
	}
}

func handle(localTCPConn *net.TCPConn, localTLSConfig *tls.Config, remoteAddr string, prox *proxy.Proxy) {
	var (
		localTLSConn *tls.Conn
		localConn    io.ReadWriter
	)

	if localTLSConfig != nil {
		localTLSConn = tls.Server(localTCPConn, localTLSConfig)
		defer localTLSConn.Close()
		localConn = localTLSConn
	} else {
		defer localTCPConn.Close()
		localConn = localTCPConn
	}

	tag := localTCPConn.RemoteAddr().String()
	log.Printf("%s: connect", tag)
	defer log.Printf("%s: disconnect", tag)

	remoteConn, err := prox.Dial("tcp", remoteAddr, nil)
	if err != nil {
		log.Printf("%s: %v", tag, err)
		return
	}
	defer remoteConn.Close()

	sendDone := make(chan struct{})
	recvDone := make(chan struct{})

	go transfer(sendDone, tag+": send", remoteConn, localConn)
	go transfer(recvDone, tag+": recv", localConn, remoteConn)

	for sendDone != nil || recvDone != nil {
		select {
		case <-sendDone:
			sendDone = nil
			if localTLSConn == nil {
				localTCPConn.CloseRead()
			}

		case <-recvDone:
			recvDone = nil
			if localTLSConn != nil {
				localTLSConn.CloseWrite()
			} else {
				localTCPConn.CloseWrite()
			}
		}
	}
}

func transfer(done chan<- struct{}, tag string, dest io.Writer, src io.Reader) {
	defer close(done)

	if _, err := io.Copy(dest, src); err == nil {
		log.Printf("%s done", tag)
	} else {
		log.Printf("%s: %v", tag, err)
	}
}
