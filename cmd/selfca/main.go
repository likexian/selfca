/*
 * Copyright 2014-2021 Li Kexian
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

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/likexian/selfca"
)

func main() {
	name := flag.String("n", "", "Common name of the certificate")
	host := flag.String("h", "", "Domains or IPs of the certificate, comma separated")
	bits := flag.Int("b", 2048, "Number of bits in the key to create (default 2048)")
	start := flag.String("s", "", "Valid from of the certificate, formatted as 2006-01-02 15:04:05 (default now)")
	days := flag.Int("d", 365, "Valid days of the certificate, for example 365 (default 365 days)")
	output := flag.String("o", "cert", "Folder for saving the certificate (default cert)")
	version := flag.Bool("v", false, "Show the selfca version")
	flag.Parse()

	if *version {
		fmt.Println("selfca version " + selfca.Version())
		fmt.Println(selfca.Author())
		os.Exit(0)
	}

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

	var caCertificate []*x509.Certificate
	var caKey *rsa.PrivateKey
	var certificate []byte
	var key *rsa.PrivateKey
	var err error

	caPath := fmt.Sprintf("%s/ca", *output)
	if _, err := os.Stat(caPath + ".crt"); err == nil {
		caCertificate, caKey, err = selfca.ReadCertificate(caPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load ca certificate: %v\n", err)
			os.Exit(1)
		}
	} else {
		caNotAfter := notBefore.Add(10 * 365 * 24 * time.Hour)
		certificate, caKey, err = selfca.GenerateCertificate(selfca.Certificate{
			IsCA:      true,
			KeySize:   *bits,
			NotBefore: notBefore,
			NotAfter:  caNotAfter,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate ca certificate: %v\n", err)
			os.Exit(1)
		}

		err = selfca.WriteCertificate(caPath, certificate, caKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write ca certificate: %v\n", err)
			os.Exit(1)
		}

		caCertificate, err = x509.ParseCertificates(certificate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse ca certificate: %v\n", err)
			os.Exit(1)
		}
	}

	certificate, key, err = selfca.GenerateCertificate(selfca.Certificate{
		IsCA:          false,
		CommonName:    *name,
		KeySize:       *bits,
		NotBefore:     notBefore,
		NotAfter:      notAfter,
		Hosts:         hosts,
		CAKey:         caKey,
		CACertificate: caCertificate[0],
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate the certificate: %v\n", err)
		os.Exit(1)
	}

	err = selfca.WriteCertificate(fmt.Sprintf("%s/%s", *output, hosts[0]), certificate, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write the certificate: %v\n", err)
		os.Exit(1)
	}
}
