/*
 * Copyright 2014-2020 Li Kexian
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
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/likexian/gokit/assert"
)

func TestVersion(t *testing.T) {
	assert.Contains(t, Version(), ".")
	assert.Contains(t, Author(), "likexian")
	assert.Contains(t, License(), "Apache License")
}

func TestGenerateCertificate(t *testing.T) {
	certPath := "cert"
	caPath := certPath + "/ca"

	config := Certificate{
		IsCA:      true,
		KeySize:   4096,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(365) * 24 * time.Hour),
	}

	certificate, key, err := GenerateCertificate(config)
	assert.Nil(t, err)
	assert.NotNil(t, key)
	assert.NotNil(t, certificate)

	_ = os.Mkdir(certPath, 0755)
	defer os.RemoveAll(certPath)

	err = WriteCertificate(caPath, certificate, key)
	assert.Nil(t, err)

	caCertificate, key, err := ReadCertificate(caPath)
	assert.Nil(t, err)

	config = Certificate{
		IsCA:          false,
		CommonName:    "likexian.com",
		NotBefore:     time.Now(),
		NotAfter:      time.Now().Add(time.Duration(365) * 24 * time.Hour),
		Hosts:         []string{"127.0.0.1", "likexian.com"},
		CAKey:         key,
		CACertificate: caCertificate[0],
	}

	certificate, key, err = GenerateCertificate(config)
	assert.Nil(t, err)
	assert.NotNil(t, key)
	assert.NotNil(t, certificate)
}

func TestReadWriteCertificate(t *testing.T) {
	certPath := "cert"
	caPath := certPath + "/ca"

	err := WriteCertificate("not-exists/ca", nil, nil)
	assert.NotNil(t, err)

	_, _, err = ReadCertificate("not-exists/ca")
	assert.NotNil(t, err)

	_ = os.Mkdir(certPath, 0755)
	defer os.RemoveAll(certPath)

	_ = ioutil.WriteFile(caPath+".crt", []byte("0"), 0644)
	_, _, err = ReadCertificate(caPath)
	assert.NotNil(t, err)

	config := Certificate{
		IsCA:      true,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(365) * 24 * time.Hour),
	}

	certificate, key, err := GenerateCertificate(config)
	assert.Nil(t, err)

	err = WriteCertificate(caPath, certificate, key)
	assert.Nil(t, err)

	os.Remove(caPath + ".key")
	_, _, err = ReadCertificate(caPath)
	assert.NotNil(t, err)

	_ = ioutil.WriteFile(caPath+".key", []byte("0"), 0644)
	_, _, err = ReadCertificate(caPath)
	assert.NotNil(t, err)
}
