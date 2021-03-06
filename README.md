go-seckeychain
==============

Native OS X Security.framework binding for Golang.

Usage
-----

    import (
        "os"
        "github.com/iwat/go-seckeychain"
    )
    
    func testFindInternet() {
        password, err := seckeychain.FindInternetPassword("example.com", "", "admin", "", uint16(22), seckeychain.ProtocolTypeSSH, seckeychain.AuthenticationTypeAny)
        if err != nil {
            println(err.Error())
            os.Exit(2)
        }

        println(password)
    }

    func testFindGeneric() {
        password, err := seckeychain.FindGenericPassword("example.com", "admin")
        if err != nil {
            println(err.Error())
            os.Exit(2)
        }

        println(password)
    }

Legal
-----

This application is developed under MIT license, and can be used for open and
proprietary projects.

Copyright (c) 2015 Chaiwat Shuetrakoonpaiboon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
