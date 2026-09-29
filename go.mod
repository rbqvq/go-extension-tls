module gitlab.com/go-extension/tls

go 1.27.0

require (
	github.com/RyuaNerin/go-krypto v1.3.0
	github.com/andybalholm/brotli v1.2.5
	github.com/blang/semver/v4 v4.0.0
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d
	github.com/emmansun/gmsm v0.44.1
	github.com/klauspost/compress v1.20.1
	github.com/pmorjan/kmod v1.1.1
	github.com/rogpeppe/go-internal v1.14.1
	gitlab.com/go-extension/aes-ccm v0.0.0-20230221065045-e58665ef23c7
	gitlab.com/go-extension/ffdh v0.0.0-20251208192952-367b797915cb
	gitlab.com/go-extension/hash v0.0.0-20250912170447-263d1d8375e4
	gitlab.com/go-extension/io v0.0.0-20260929105507-614496a44375
	gitlab.com/go-extension/rand v0.0.0-20240303103951-707937a049b5
	gitlab.com/go-extension/utils v0.0.0-20251006173700-b62b19cda891
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
)

require github.com/cronokirby/saferith v0.33.1-0.20250226174546-1f11f94ce488 // indirect

replace github.com/rogpeppe/go-internal => github.com/rbqvq/go-internal v0.0.0-20260927144954-85efeaec562b
