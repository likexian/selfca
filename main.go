/*
 * Copyright 2014-2017 Li Kexian
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Go module for Self-Signed Certificate Generating
 * https://www.likexian.com/
 */

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// Certificate stors certificate information for generating
type Certificate struct {
	isCa          bool
	hosts         []string
	caKey         *rsa.PrivateKey
	caCertificate *x509.Certificate
	notBefore     time.Time
	notAfter      time.Time
}

func main() {
	host := flag.String("h", "", "Domains or IPs of the certificate, comma separated")
	start := flag.String("s", "", "Valid from of the certificate, formatted as 2006-01-02 15:04:05 (default now)")
	days := flag.Int("d", 365, "Valid days of the certificate, for example 365 (default 365 days)")
	output := flag.String("o", "cert", "Folder for saving the certificate (default cert)")
	flag.Parse()

	var hosts []string
	for _, v := range strings.Split(*host, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			hosts = append(hosts, v)
		}
	}

	if len(hosts) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	var notBefore time.Time
	if len(*start) == 0 {
		notBefore = time.Now()
	} else {
		var err error
		notBefore, err = time.Parse("2006-01-02 15:04:05", *start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse valid from parameter: %v\n", err)
			os.Exit(1)
		}
	}

	notAfter := notBefore.Add(time.Duration(*days) * 24 * time.Hour)

	if len(*output) == 0 {
		*output = "cert"
	}

	if _, err := os.Stat(*output); os.IsNotExist(err) {
		err = os.MkdirAll(*output, 0755)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output folder: %v\n", err)
			os.Exit(1)
		}
	}

	certificate, key, err := GenerateCertificate(Certificate{isCa: true, notBefore: notBefore, notAfter: notAfter})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate ca certificate: %v\n", err)
		os.Exit(1)
	}

	err = WriteCertificate(fmt.Sprintf("%s/ca", *output), certificate, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write ca certificate: %v\n", err)
		os.Exit(1)
	}

	caCertificate, err := x509.ParseCertificates(certificate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse ca certificate: %v\n", err)
		os.Exit(1)
	}

	certificate, key, err = GenerateCertificate(Certificate{isCa: false, hosts: hosts, caKey: key, caCertificate: caCertificate[0], notBefore: notBefore, notAfter: notAfter})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate the certificate: %v\n", err)
		os.Exit(1)
	}

	err = WriteCertificate(fmt.Sprintf("%s/%s", *output, hosts[0]), certificate, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write the certificate: %v\n", err)
		os.Exit(1)
	}
}

// GenerateCertificate generates X.509 certificate and key
func GenerateCertificate(c Certificate) ([]byte, *rsa.PrivateKey, error) {
	serialNumberMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberMax)
	if err != nil {
		return nil, nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{},
		NotBefore:             c.notBefore,
		NotAfter:              c.notAfter,
		IsCA:                  c.isCa,
		BasicConstraintsValid: true,
	}

	if c.isCa {
		template.Subject.CommonName = "Root CA"
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		c.caKey = key
		c.caCertificate = &template
	} else {
		template.Subject.CommonName = c.hosts[0]
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	for _, v := range c.hosts {
		if ip := net.ParseIP(v); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, v)
		}
	}

	certificate, err := x509.CreateCertificate(rand.Reader, &template, c.caCertificate, &key.PublicKey, c.caKey)
	if err != nil {
		return nil, nil, err
	}

	return certificate, key, nil
}

// WriteCertificate writes certificate and key to files
func WriteCertificate(name string, certificate []byte, key *rsa.PrivateKey) error {
	certificateName := fmt.Sprintf("%s.crt", name)
	fd, err := os.Create(certificateName)
	if err != nil {
		return err
	}

	err = pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return err
	}
	fd.Close()

	keyName := fmt.Sprintf("%s.key", name)
	fd, err = os.Create(keyName)
	if err != nil {
		return err
	}

	err = pem.Encode(fd, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return err
	}
	fd.Close()

	return nil
}
