// go-seckeychain - Native OS X Security.framework binding for Golang

// Copyright (c) 2015 Chaiwat Shuetrakoonpaiboon. All rights reserved.
//
// Use of this source code is governed by a MIT license that can be found in
// the LICENSE file.

// +build !darwin !cgo

package seckeychain

// See https://developer.apple.com/library/mac/documentation/Security/Reference/keychainservices/index.html for the APIs used below.

// Also see https://developer.apple.com/library/ios/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html .

type AuthenticationType int

// From http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-34101/lib/SecKeychain.h
const (
	AuthenticationTypeNTLM = iota
	AuthenticationTypeMSN
	AuthenticationTypeDPA
	AuthenticationTypeRPA
	AuthenticationTypeHTTPBasic
	AuthenticationTypeHTTPDigest
	AuthenticationTypeHTMLForm
	AuthenticationTypeDefault
	AuthenticationTypeAny
)
