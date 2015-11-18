// +build darwin,cgo

package seckeychain

import (
	"os"
)

func ExampleFindInternetPassword() {
	password, err := FindInternetPassword("example.com", "", "admin", "", uint16(22), ProtocolTypeSSH, AuthenticationTypeAny)
	if err != nil {
		println(err.Error())
		os.Exit(2)
	}

	println(password)
}

func ExampleFindGenericPassword() {
	password, err := FindGenericPassword("example.com", "admin")
	if err != nil {
		println(err.Error())
		os.Exit(2)
	}

	println(password)
}
