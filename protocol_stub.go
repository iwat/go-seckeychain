// +build !darwin !cgo

package seckeychain

// See https://developer.apple.com/library/mac/documentation/Security/Reference/keychainservices/index.html for the APIs used below.

// Also see https://developer.apple.com/library/ios/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html .

type ProtocolType int

// From http://www.opensource.apple.com/source/libsecurity_
const (
	ProtocolTypeFTP = iota
	ProtocolTypeFTPAccount
	ProtocolTypeHTTP
	ProtocolTypeIRC
	ProtocolTypeNNTP
	ProtocolTypePOP3
	ProtocolTypeSMTP
	ProtocolTypeSOCKS
	ProtocolTypeIMAP
	ProtocolTypeLDAP
	ProtocolTypeAppleTal
	ProtocolTypeAFP
	ProtocolTypeTelnet
	ProtocolTypeSSH
	ProtocolTypeFTPS
	ProtocolTypeHTTPS
	ProtocolTypeHTTPProxy
	ProtocolTypeHTTPSProxy
	ProtocolTypeFTPProxy
	ProtocolTypeCIFS
	ProtocolTypeSMB
	ProtocolTypeRTSP
	ProtocolTypeRTSPProxy
	ProtocolTypeDAAP
	ProtocolTypeEPPC
	ProtocolTypeIPP
	ProtocolTypeNNTPS
	ProtocolTypeLDAPS
	ProtocolTypeTelnetS
	ProtocolTypeIMAPS
	ProtocolTypeIRCS
	ProtocolTypePOP3S
	ProtocolTypeCVSpserver
	ProtocolTypeSVN
	ProtocolTypeAny
)
