// go-seckeychain - Native OS X Security.framework binding for Golang

// Copyright (c) 2015 Chaiwat Shuetrakoonpaiboon. All rights reserved.
//
// Use of this source code is governed by a MIT license that can be found in
// the LICENSE file.

// +build darwin,cgo

package seckeychain

// See https://developer.apple.com/library/mac/documentation/Security/Reference/keychainservices/index.html for the APIs used below.

// Also see https://developer.apple.com/library/ios/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html .

/*
#cgo CFLAGS: -mmacosx-version-min=10.6 -D__MAC_OS_X_VERSION_MAX_ALLOWED=1060
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

type ProtocolType C.SecProtocolType

// From http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-34101/lib/SecKeychain.h
const (
	ProtocolTypeFTP        = C.kSecProtocolTypeFTP
	ProtocolTypeFTPAccount = C.kSecProtocolTypeFTPAccount
	ProtocolTypeHTTP       = C.kSecProtocolTypeHTTP
	ProtocolTypeIRC        = C.kSecProtocolTypeIRC
	ProtocolTypeNNTP       = C.kSecProtocolTypeNNTP
	ProtocolTypePOP3       = C.kSecProtocolTypePOP3
	ProtocolTypeSMTP       = C.kSecProtocolTypeSMTP
	ProtocolTypeSOCKS      = C.kSecProtocolTypeSOCKS
	ProtocolTypeIMAP       = C.kSecProtocolTypeIMAP
	ProtocolTypeLDAP       = C.kSecProtocolTypeLDAP
	ProtocolTypeAppleTalk  = C.kSecProtocolTypeAppleTalk
	ProtocolTypeAFP        = C.kSecProtocolTypeAFP
	ProtocolTypeTelnet     = C.kSecProtocolTypeTelnet
	ProtocolTypeSSH        = C.kSecProtocolTypeSSH
	ProtocolTypeFTPS       = C.kSecProtocolTypeFTPS
	ProtocolTypeHTTPS      = C.kSecProtocolTypeHTTPS
	ProtocolTypeHTTPProxy  = C.kSecProtocolTypeHTTPProxy
	ProtocolTypeHTTPSProxy = C.kSecProtocolTypeHTTPSProxy
	ProtocolTypeFTPProxy   = C.kSecProtocolTypeFTPProxy
	ProtocolTypeCIFS       = C.kSecProtocolTypeCIFS
	ProtocolTypeSMB        = C.kSecProtocolTypeSMB
	ProtocolTypeRTSP       = C.kSecProtocolTypeRTSP
	ProtocolTypeRTSPProxy  = C.kSecProtocolTypeRTSPProxy
	ProtocolTypeDAAP       = C.kSecProtocolTypeDAAP
	ProtocolTypeEPPC       = C.kSecProtocolTypeEPPC
	ProtocolTypeIPP        = C.kSecProtocolTypeIPP
	ProtocolTypeNNTPS      = C.kSecProtocolTypeNNTPS
	ProtocolTypeLDAPS      = C.kSecProtocolTypeLDAPS
	ProtocolTypeTelnetS    = C.kSecProtocolTypeTelnetS
	ProtocolTypeIMAPS      = C.kSecProtocolTypeIMAPS
	ProtocolTypeIRCS       = C.kSecProtocolTypeIRCS
	ProtocolTypePOP3S      = C.kSecProtocolTypePOP3S
	ProtocolTypeCVSpserver = C.kSecProtocolTypeCVSpserver
	ProtocolTypeSVN        = C.kSecProtocolTypeSVN
	ProtocolTypeAny        = C.kSecProtocolTypeAny
)
