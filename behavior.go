// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// A UselessRecordCount structure is a counter to configure a TLS client or server behavior.
type UselessRecordCount struct {
	WarningAlerts    int
	Empty            int
	ChangeCipherSpec int // Only for TLS 1.3+
}

// A Behavior structure is used to configure a TLS client or server behavior.
type Behavior struct {
	// MaxUselessRecords is used to control the maximum of useless records received.
	// An alert will be thrown when this value is exceeded.
	// If the value is <= 0, it means no limit.
	MaxUselessRecords int

	// CheckUselessRecordsCount is used to check useless records by type.
	// If is nil, it means no limit. If it return false, an alert will be thrown.
	CheckUselessRecordsCount func(count UselessRecordCount) bool

	// Alert is a notification about an error.
	Alert AlertBehavior

	// ChangeCipherSpec is a notification about a change in encryption scheme.
	//
	// RFC 8446 deprecates this message and all TLS 1.3 implementations MUST ignore it.
	// There is no requirement for it to be sent, but almost all clients send it for legacy
	// versions of the protocol to ensure middlebox compatibility.
	ChangeCipherSpec ChangeCipherSpecBehavior

	// SendTicketOnCompleted controls whether the session ticket is sent after 
	// the TLS 1.3 handshake is completed.
	SendTicketOnCompleted bool
}

// A ChangeCipherSpecBehavior structure is used to configure a TLS client or server behavior
// when received a ChangeCipherSpec.
type ChangeCipherSpecBehavior struct {
	// DecodeResponse controls the response to errors when parsing a message.
	// If not set, decode_error will be sent.
	DecodeResponse uint8

	// DecodeResponseTLS13 controls the response to errors when parsing a message on TLS 1.3.
	// If not set, follow the DecodeResponse.
	DecodeResponseTLS13 uint8

	// RejectPlaintextAfterEncrypted is used to control the behavior of receiving a
	// plaintext ChangeCipherSpec after receiving encrypted messages on TLS 1.3.
	// If true, an bad_record_mac alert will be sent after receiving
	RejectPlaintextAfterEncrypted bool

	// RejectCCSAfterEncrypted is used to control the behavior of receiving ChangeCipherSpec
	// after receiving encrypted messages on TLS 1.3.
	// If true, an unexpected_message alert will be sent after receiving
	RejectAfterEncrypted bool
}

// A AlertBehavior structure is used to configure a TLS client or server behavior
// when received a Alert.
type AlertBehavior struct {
	// DecodeResponse controls the response to errors when parsing a message.
	// If not set, unexpected_message will be sent.
	DecodeResponse uint8

	// If true, any alerts with unknown levels will be treated as warning on TLS 1.0-1.2.
	UnknownAsWarning bool

	// If true, any alerts with unknown levels will be treated as warning.
	UnknownResponse uint8

	// DisableIgnoreUserCanceled is used to control the behavior of receiving a
	// user_canceled alert on TLS 1.3.
	// If true, an error will be sent after receiving
	DisableIgnoreUserCanceled bool

	// DisableIgnoreFatalUserCanceled is used to control the behavior of receiving a
	// user_canceled alert with fatal level on TLS 1.3
	// If true, an error will be sent after receiving
	DisableIgnoreFatalUserCanceled bool

	// If true, a decode_error will be sent for all warning alerts except for close_notify
	// and user_canceled on TLS 1.3.
	LevelCheck bool

	// DisableCloseNotify is used to control the behavior of Close.
	// If true, close_notify will not be sent.
	DisableCloseNotify bool
}
