/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"github.com/hyperledger/fabric-cop/cli/server"
	"github.com/hyperledger/fabric/core/crypto/bccsp/factory"
	"github.com/hyperledger/fabric/core/crypto/bccsp/sw"
	"os"
	"strings"
	"testing"
)

func TestClientCommand(t *testing.T) {
	rtn := COPMain([]string{"cop", "client"})
	if rtn == 0 {
		t.Error("TestClientCommand passed but should have failed")
	}
}

func TestServerCommand(t *testing.T) {
	rtn := COPMain([]string{"cop", "server"})
	if rtn == 0 {
		t.Error("TestServerCommand passed but should have failed")
	}
}

func TestCFSSLCommand(t *testing.T) {
	rtn := COPMain([]string{"cop", "cfssl"})
	if rtn == 0 {
		t.Error("TestCFSSLCommand passed but should have failed")
	}
}

func TestBogusCommand(t *testing.T) {
	rtn := COPMain([]string{"cop", "bogus"})
	if rtn == 0 {
		t.Error("TestBogusCommand passed but should have failed")
	}
}

// This 'test' is provided as a utility to convert from PEM encoded
// software keys into BCCSP SKI files when new tests are being added
// For example:
//   go test -run TestGenerateSKIsFromPEM -args ../testdata/ec-key.pem ../testdata/test-key.pem
func TestGenerateSKIsFromPEM(t *testing.T) {
	t.SkipNow()

	ks := &sw.FileBasedKeyStore{}
	err := ks.Init(nil, "../testdata/ks", false)
	if err != nil {
		t.Fatalf("Failed initializing key store [%s]", err)
	}

	// For now hardcode the SW BCCSP. This should be made parametrizable via json cfg once there are more BCCSPs
	bccspOpts := &factory.SwOpts{Ephemeral_: true, SecLevel: 256, HashFamily: "SHA2", KeyStore: ks}
	csp, err := factory.GetBCCSP(bccspOpts)
	if err != nil {
		t.Fatalf("Failed getting BCCSP [%s]", err)
	}

	for _, name := range os.Args[2:] {
		fmt.Printf("Parm to test is %s\n", name)
		server.PEMKeyToSKI(csp, name, strings.Replace(name, ".pem", ".ski", 1))
	}
}
