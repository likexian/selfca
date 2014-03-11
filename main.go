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

func main() {
	domain := flag.String("domain", "", "Domains or IPs of the certificate, comma separated")
	start := flag.String("start", "", "Valid from of the certificate, formatted as 2006-01-02 15:04:05 (default now)")
	duration := flag.Duration("duration", 365*24*time.Hour, "Valid duration of the certificate, for example 24h (default 1year)")
	flag.Parse()

	if len(*domain) == 0 {
		fmt.Fprintf(os.Stderr, "The domain parameter is required\n")
		os.Exit(1)
	}

	var notBefore time.Time
	if len(*start) == 0 {
		notBefore = time.Now()
	} else {
		var err error
		notBefore, err = time.Parse("2006-01-02 15:04:05", *start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse start parameter: %v\n", err)
			os.Exit(1)
		}
	}

	notAfter := notBefore.Add(*duration)

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate ca key: %v\n", err)
		os.Exit(1)
	}

	err = writeKey("ca.key", caKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write ca key: %v\n", err)
		os.Exit(1)
	}

	serialNumberMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberMax)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate serial number: %v\n", err)
		os.Exit(1)
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:    "Root CA",
			Organization:  []string{"Example, INC."},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ca certificate: %v\n", err)
		os.Exit(1)
	}

	err = writeCert("ca.crt", derBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write ca certificate: %v\n", err)
		os.Exit(1)
	}

	domainKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate domain key: %v\n", err)
		os.Exit(1)
	}

	err = writeKey("domain.key", domainKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write domain key: %v\n", err)
		os.Exit(1)
	}

	serialNumber, err = rand.Int(rand.Reader, serialNumberMax)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate serial number: %v\n", err)
		os.Exit(1)
	}

	domainTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:    "www.example.com",
			Organization:  []string{"Example, INC."},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	for _, domain := range strings.Split(*domain, ",") {
		if ip := net.ParseIP(domain); ip != nil {
			domainTemplate.IPAddresses = append(domainTemplate.IPAddresses, ip)
		} else {
			domainTemplate.DNSNames = append(domainTemplate.DNSNames, domain)
		}
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &domainTemplate, &caTemplate, &domainKey.PublicKey, caKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create domain certificate: %v\n", err)
		os.Exit(1)
	}

	err = writeCert("domain.crt", derBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write domain certificate: %v\n", err)
		os.Exit(1)
	}
}

// writeKey writes a PEM serialization key to file
func writeKey(filename string, key *rsa.PrivateKey) error {
	fd, err := os.Create(filename)
	if err != nil {
		return err
	}

	err = pem.Encode(fd, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return err
	}

	return fd.Close()
}

// writeCert writes a certificate to file
func writeCert(filename string, derBytes []byte) error {
	fd, err := os.Create(filename)
	if err != nil {
		return err
	}

	err = pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return err
	}

	return fd.Close()
}
