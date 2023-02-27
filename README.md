# Transport Layer Security (TLS)

This repository is an extension of the golang standard library [crypto/go](https://pkg.go.dev/crypto/go)

# Currently implements more TLS functions than the standard library

- AES CCM cipher
- ARIA cipher
- CEMALLIA cipher
- Kernel TLS
- TLS 1.3 0RTT (Early Data) [ONLY FOR SERVER]
- Compressed certificate
- Application-Layer Protocol Settings (ALPS)
- GREASE
- Custom cipher suites order
- Custom cipher suites in tls 1.3
- Custom supported version list
- Custom extension

# TODO

- TLS 1.3 0RTT (Early Data) [Client side]
- QUIC QTLS

# Special thanks

- [uTLS](https://github.com/refraction-networking/utls)
- [Cloudflare tls-tris](https://github.com/cloudflare/tls-tris)
- [goktls](https://github.com/secure-for-ai/goktls/)
