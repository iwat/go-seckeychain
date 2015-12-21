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

type AuthenticationType C.SecAuthenticationType

// From http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-34101/lib/SecKeychain.h
const (
	AuthenticationTypeNTLM       = C.kSecAuthenticationTypeNTLM
	AuthenticationTypeMSN        = C.kSecAuthenticationTypeMSN
	AuthenticationTypeDPA        = C.kSecAuthenticationTypeDPA
	AuthenticationTypeRPA        = C.kSecAuthenticationTypeRPA
	AuthenticationTypeHTTPBasic  = C.kSecAuthenticationTypeHTTPBasic
	AuthenticationTypeHTTPDigest = C.kSecAuthenticationTypeHTTPDigest
	AuthenticationTypeHTMLForm   = C.kSecAuthenticationTypeHTMLForm
	AuthenticationTypeDefault    = C.kSecAuthenticationTypeDefault
	AuthenticationTypeAny        = C.kSecAuthenticationTypeAny
)
