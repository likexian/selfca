# SelfCA

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

Copyright 2014-2020 [Li Kexian](https://www.likexian.com/)

Licensed under the Apache License 2.0

## Donation

If this project is helpful, please share it with friends.

If you want to thank me, you can [give me a cup of coffee](https://www.likexian.com/donate/).