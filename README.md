# SelfCA

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/likexian/selfca?status.svg)](https://godoc.org/github.com/likexian/selfca)
[![Build Status](https://travis-ci.org/likexian/selfca.svg?branch=master)](https://travis-ci.org/likexian/selfca)
[![Go Report Card](https://goreportcard.com/badge/github.com/likexian/selfca)](https://goreportcard.com/report/github.com/likexian/selfca)
[![Code Cover](https://codecov.io/gh/likexian/selfca/graph/badge.svg)](https://codecov.io/gh/likexian/selfca)

SelfCA is a Go module for self-signed certificate generating.

## Overview

Creating your own certificate authority and generating self-signed SSL certificates.

## Features

- Easy to use
- No openssl required
- Reuse CA certificate

## Installation

```shell
go get -u github.com/likexian/selfca
```

## Importing

```go
import (
    "github.com/likexian/selfca"
)
```

## Documentation

Visit the docs on [GoDoc](https://godoc.org/github.com/likexian/selfca)

## Example

```go
// config for generating CA certificate
config := selfca.Certificate{
    IsCA:          true,
    NotBefore:     time.Now(),
    NotAfter:      time.Now().Add(time.Duration(365) * 24 * time.Hour),
}

// generating the certificate
certificate, key, err := selfca.GenerateCertificate(config)
if err != nil {
    panic(err)
}

// writing the certificate
err = selfca.WriteCertificate("ca", certificate, key)
if err != nil {
    panic(err)
}
```

## License

Copyright 2014-2021 [Li Kexian](https://www.likexian.com/)

Licensed under the Apache License 2.0

## Donation

If this project is helpful, please share it with friends.

If you want to thank me, you can [give me a cup of coffee](https://www.likexian.com/donate/).
