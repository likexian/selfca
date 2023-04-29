/*
 * Copyright 2014-2023 Li Kexian
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
 * Go module for self-signed certificate generating
 * https://www.likexian.com/
 */

package selfca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

var (
	// ErrInvalidCertificate is invalid certificate error
	ErrInvalidCertificate = errors.New("selfca: the certificate is invalid")
	// ErrInvalidCertificateKey is invalid certificate key error
	ErrInvalidCertificateKey = errors.New("selfca: the certificate key is invalid")
)

// Certificate stors certificate information for generating
type Certificate struct {
	IsCA          bool
	CommonName    string
	KeySize       int
	NotBefore     time.Time
	NotAfter      time.Time
	Hosts         []string
	CAKey         *rsa.PrivateKey
	CACertificate *x509.Certificate
}

// Version returns package version
func Version() string {
	return "v0.14.4"
}

// Author returns package author
func Author() string {
	return "[Li Kexian](https://www.likexian.com/)"
}

// License returns package license
func License() string {
	return "Licensed under the Apache License 2.0"
}

// GenerateCertificate generates X.509 certificate and key
func GenerateCertificate(c Certificate) ([]byte, *rsa.PrivateKey, error) {
	serialNumberMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberMax)
	if err != nil {
		return nil, nil, err
	}

	if c.KeySize <= 0 {
		c.KeySize = 2048
	}

	key, err := rsa.GenerateKey(rand.Reader, c.KeySize)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{},
		NotBefore:             c.NotBefore,
		NotAfter:              c.NotAfter,
		IsCA:                  c.IsCA,
		BasicConstraintsValid: true,
	}

	if c.IsCA {
		template.Subject.CommonName = "Root CA"
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		c.CAKey = key
		c.CACertificate = &template
	} else {
		template.Subject.CommonName = c.Hosts[0]
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	if c.CommonName != "" {
		template.Subject.CommonName = c.CommonName
	}

	for _, v := range c.Hosts {
		if ip := net.ParseIP(v); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, v)
		}
	}

	certificate, err := x509.CreateCertificate(rand.Reader,
		&template, c.CACertificate, &key.PublicKey, c.CAKey)

	return certificate, key, err
}

// ReadCertificate reads certificate and key from files
func ReadCertificate(name string) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	certificateName := fmt.Sprintf("%s.crt", name)
	fd, err := os.Open(certificateName)
	if err != nil {
		return nil, nil, err
	}

	defer fd.Close()
	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, nil, err
	}

	p, _ := pem.Decode(data)
	if p == nil {
		return nil, nil, ErrInvalidCertificate
	}

	certificate, err := x509.ParseCertificates(p.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyName := fmt.Sprintf("%s.key", name)
	fd, err = os.Open(keyName)
	if err != nil {
		return nil, nil, err
	}

	defer fd.Close()
	data, err = ioutil.ReadAll(fd)
	if err != nil {
		return nil, nil, err
	}

	p, _ = pem.Decode(data)
	if p == nil {
		return nil, nil, ErrInvalidCertificateKey
	}

	key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
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

	defer fd.Close()
	err = pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return err
	}

	keyName := fmt.Sprintf("%s.key", name)
	fd, err = os.Create(keyName)
	if err != nil {
		return err
	}

	defer fd.Close()
	err = pem.Encode(fd, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return err
	}

	return nil
}
