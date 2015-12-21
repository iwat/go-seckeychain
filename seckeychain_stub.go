// go-seckeychain - Native OS X Security.framework binding for Golang

// Copyright (c) 2015 Chaiwat Shuetrakoonpaiboon. All rights reserved.
//
// Use of this source code is governed by a MIT license that can be found in
// the LICENSE file.

// +build !darwin !cgo

package seckeychain

import (
	"errors"
)

func FindInternetPassword(server, domain, account, path string, port uint16, protocol ProtocolType, authType AuthenticationType) (string, error) {
	return "", errors.New("seckeychain: FindInternetPassword is only available on OSX")
}

func FindGenericPassword(service, account string) (string, error) {
	return "", errors.New("seckeychain: FindGenericPassword is only available on OSX")
}
