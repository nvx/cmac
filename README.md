[![Go Reference](https://pkg.go.dev/badge/github.com/nvx/cmac.svg)](https://pkg.go.dev/github.com/nvx/cmac)

## The CMAC/OMAC1 message authentication code

The CMAC message authentication code is specified (with AES) in [RFC 4493](https://tools.ietf.org/html/rfc4493 "RFC 4493")
and [RFC 4494](https://tools.ietf.org/html/rfc4494 "RFC 4494").  
CMAC is only specified with the AES.  

This implementation supports block ciphers with a block size of 64, 128, 256, 512 or 1024 bit.

Forked from [aead/cmac](https://github.com/aead/cmac)

### Installation
Install in your GOPATH: `go get -u github.com/nvx/cmac`  
