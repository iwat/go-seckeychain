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
	"fmt"
)

type keychainError C.OSStatus

// Error codes from https://developer.apple.com/library/mac/documentation/security/Reference/keychainservices/Reference/reference.html#//apple_ref/doc/uid/TP30000898-CH5g-CJBEABHG
const (
	ErrUnimplemented     keychainError = C.errSecUnimplemented
	ErrParam             keychainError = C.errSecParam
	ErrAllocate          keychainError = C.errSecAllocate
	ErrNotAvailable      keychainError = C.errSecNotAvailable
	ErrReadOnly          keychainError = C.errSecReadOnly
	ErrAuthFailed        keychainError = C.errSecAuthFailed
	ErrNoSuchKeychain    keychainError = C.errSecNoSuchKeychain
	ErrInvalidKeychain   keychainError = C.errSecInvalidKeychain
	ErrDuplicateKeychain keychainError = C.errSecDuplicateKeychain
	ErrDuplicateCallback keychainError = C.errSecDuplicateCallback
	ErrInvalidCallback   keychainError = C.errSecInvalidCallback
	ErrDuplicateItem     keychainError = C.errSecDuplicateItem
	ErrItemNotFound      keychainError = C.errSecItemNotFound
	ErrBufferTooSmall    keychainError = C.errSecBufferTooSmall
	ErrDataTooLarge      keychainError = C.errSecDataTooLarge
	ErrNoSuchAttr        keychainError = C.errSecNoSuchAttr
	ErrInvalidItemRef    keychainError = C.errSecInvalidItemRef
	ErrInvalidSearchRef  keychainError = C.errSecInvalidSearchRef
	ErrNoSuchClass       keychainError = C.errSecNoSuchClass
	ErrNoDefaultKeychain keychainError = C.errSecNoDefaultKeychain
	ErrReadOnlyAttr      keychainError = C.errSecReadOnlyAttr
	// TODO: Fill out more of these?
)

func newKeychainError(errCode C.OSStatus) error {
	if errCode == C.noErr {
		return nil
	}
	return keychainError(errCode)
}

func (ke keychainError) Error() string {
	errorMessageCFString := C.SecCopyErrorMessageString(C.OSStatus(ke), nil)
	defer C.CFRelease(C.CFTypeRef(errorMessageCFString))

	errorMessageCString := C.CFStringGetCStringPtr(errorMessageCFString, C.kCFStringEncodingASCII)

	if errorMessageCString != nil {
		return C.GoString(errorMessageCString)
	}

	return fmt.Sprintf("keychainError with unknown error code %d", C.OSStatus(ke))
}
