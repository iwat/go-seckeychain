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

// Finds the first Internet password item that matches the attributes you
// provide in pass. Some attributes, such as ServerName and AccountName may be
// left blank, in which case they will be ignored in the search.
//
// Returns an error if the lookup was unsuccessful.
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
