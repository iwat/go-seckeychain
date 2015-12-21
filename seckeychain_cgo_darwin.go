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

import (
	"errors"
	"unsafe"
)

// FindInternetPassword function finds the first Internet password item which
// matches the attributes you provide. Most attributes are optional; you should
// pass only as many as you need to narrow the search sufficiently for your
// application's intended use. SecKeychainFindInternetPassword optionally
// returns a reference to the found item.
func FindInternetPassword(server, domain, account, path string, port uint16, protocol ProtocolType, authType AuthenticationType) (string, error) {
	if server == "" || account == "" {
		return "", errors.New("server and account are required")
	}

	cServer := C.CString(server)
	defer C.free(unsafe.Pointer(cServer))

	cDomain := C.CString(domain)
	defer C.free(unsafe.Pointer(cDomain))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cPasswordLen := C.UInt32(0)
	cPassword := unsafe.Pointer(nil)

	errCode := C.SecKeychainFindInternetPassword(
		nil, // default keychain,
		C.UInt32(C.strlen(cServer)),
		cServer,
		C.UInt32(C.strlen(cDomain)),
		cDomain,
		C.UInt32(C.strlen(cAccount)),
		cAccount,
		C.UInt32(C.strlen(cPath)),
		cPath,
		C.UInt16(port),
		C.SecProtocolType(protocol),
		C.SecAuthenticationType(authType),
		&cPasswordLen,
		&cPassword,
		nil,
	)

	if err := newKeychainError(errCode); err != nil {
		return "", err
	}

	defer C.SecKeychainItemFreeContent(nil, cPassword)

	return C.GoStringN((*C.char)(cPassword), C.int(cPasswordLen)), nil
}

// FindGenericPassword finds the first generic password item which matches the
// attributes you provide. Most attributes are optional; you should pass only as
// many as you need to narrow the search sufficiently for your application's
// intended use.
func FindGenericPassword(service, account string) (string, error) {
	if service == "" || account == "" {
		return "", errors.New("service and account are required")
	}

	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))

	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	cPasswordLen := C.UInt32(0)
	cPassword := unsafe.Pointer(nil)

	errCode := C.SecKeychainFindGenericPassword(
		nil, // default keychain
		C.UInt32(C.strlen(cService)),
		cService,
		C.UInt32(C.strlen(cAccount)),
		cAccount,
		&cPasswordLen,
		&cPassword,
		nil,
	)

	if err := newKeychainError(errCode); err != nil {
		return "", err
	}

	defer C.SecKeychainItemFreeContent(nil, cPassword)

	return C.GoStringN((*C.char)(cPassword), C.int(cPasswordLen)), nil
}
