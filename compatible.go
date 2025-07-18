package tls

import (
	"crypto/tls"

	"gitlab.com/go-extension/utils"
)

func (cs ConnectionState) Compatible() (tlsState tls.ConnectionState) {
	utils.Convert(&cs, &tlsState)
	return
}

func ToConnectionState(tlsState tls.ConnectionState) (cs ConnectionState) {
	utils.Convert(&tlsState, &cs)
	return
}
