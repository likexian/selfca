# SelfCA

SelfCA is a Go module for self-signed certificate generating.

## Download selfca

The latest version of selfca can be downloaded using the links below. Please download the proper package for your operating system and architecture.

SelfCA is released as a single binary file. Install selfca by unzipping it and moving it to a directory included in your system's PATH.

### macOS

- [64-bit](https://github.com/likexian/selfca/releases/latest/download/selfca-darwin-amd64.tar.gz)

### Linux

- [64-bit](https://github.com/likexian/selfca/releases/latest/download/selfca-linux-amd64.tar.gz)
- [32-bit](https://github.com/likexian/selfca/releases/latest/download/selfca-linux-386.tar.gz)

### Windows

- [64-bit](https://github.com/likexian/selfca/releases/latest/download/selfca-windows-amd64.zip)
- [32-bit](https://github.com/likexian/selfca/releases/latest/download/selfca-windows-386.zip)

## Usage

### generating certificate for one domain

```shell
selfca -h likexian.com
```

### generating certificate for multiple domain

```shell
selfca -h likexian.com,ssl.likexian.com
```

### generating certificate with Valid from and days

```shell
selfca -h likexian.com -s "2006-01-02 15:04:05" -d 3650
```

## License

Copyright 2014-2022 [Li Kexian](https://www.likexian.com/)

Licensed under the Apache License 2.0

## Donation

If this project is helpful, please share it with friends.

If you want to thank me, you can [give me a cup of coffee](https://www.likexian.com/donate/).
