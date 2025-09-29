# Transport Layer Security (TLS)

This repository is an extension of the golang standard library [crypto/go](https://pkg.go.dev/crypto/go)

# Currently implements more TLS functions than the standard library

- AES CCM cipher
- ARIA cipher
- CEMALLIA cipher
- SM4 cipher
- Kernel TLS
- Encrypt-then-MAC (RFC 7366)
- TLS 1.3 0-RTT (Early Data)
- TLS 1.3 FFDHE Key Exchange (RFC 7919)
- TLS 1.3 Delegated Credential (RFC 9345)
- Compressed certificate
- Application-Layer Protocol Settings (ALPS)
- GREASE
- Custom extension
- Custom fingerprint via [tlsfinger](https://gitlab.com/go-extension/tlsfinger)

# Special thanks

- [uTLS](https://github.com/refraction-networking/utls)
- [Cloudflare tls-tris](https://github.com/cloudflare/tls-tris)
- [Cloudflare Golang](https://github.com/cloudflare/go)
- [goktls](https://github.com/secure-for-ai/goktls/)
