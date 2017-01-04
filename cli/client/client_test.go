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

package client

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/cli"
	"github.com/hyperledger/fabric-cop/cli/server"
)

var serverStarted bool
var serverExitCode = 0

const (
	clientPath = "/tmp/clientTesting"
	KEY        = "../../testdata/ec-key.ski"
	KEYSTORE   = "../../testdata/ks"
)

func TestMain(m *testing.M) {
	startServer()
	os.Exit(m.Run())
}

// TestNewClient tests constructing a client
func TestNewClient(t *testing.T) {
	_, err := NewClient("http://127.0.0.1:8888")
	if err != nil {
		t.Errorf("Failed to create a client: %s", err)
	}
}

func TestEnrollCLI(t *testing.T) {
	c := new(cli.Config)

	args := []string{"admin", "adminpw", "http://localhost:8888"}

	err := enrollMain(args, *c)
	if err != nil {
		t.Error("Failed to register, err: ", err)
	}

}

func TestReenrollCLI(t *testing.T) {
	c := new(cli.Config)

	args := []string{"http://localhost:8888"}

	err := reenrollMain(args, *c)
	if err != nil {
		t.Error("Failed to reenroll, err: ", err)
	}

}

func TestRegister(t *testing.T) {

	c := new(cli.Config)

	args := []string{"../../testdata/registerrequest.json", "http://localhost:8888"}

	err := registerMain(args, *c)
	if err != nil {
		t.Error("Failed to register, err: ", err)
	}

}

func TestRegisterNotEnoughArgs(t *testing.T) {
	c := new(cli.Config)

	args := []string{"../../testdata/registerrequest.json"}

	err := registerMain(args, *c)
	if err == nil {
		t.Error("Should have failed, not enough arguments provided")
	}

}

func TestRegisterNoJSON(t *testing.T) {
	c := new(cli.Config)

	args := []string{"", "admin", "http://localhost:8888"}

	err := registerMain(args, *c)
	if err == nil {
		t.Error("Should result in failure if registration json file not specificied, error: ", err)
	}

}

func TestRegisterMissingRegistrar(t *testing.T) {
	c := new(cli.Config)

	// os.Setenv("COP_HOME", "/tmp")
	args := []string{"", "", "http://localhost:8888"}

	err := registerMain(args, *c)
	if err == nil {
		t.Error("Should result in failure if no registrar identity exists")
	}

}

func TestRevoke(t *testing.T) {

	c := new(cli.Config)

	args := []string{"http://localhost:8888", "admin"}

	err := revokeMain(args, *c)
	if err != nil {
		t.Errorf("TestRevoke failed: %s", err)
	}

}

func TestEnrollCLINotEnoughArgs(t *testing.T) {

	c := new(cli.Config)

	args := []string{"testUser"}

	err := enrollMain(args, *c)
	if err == nil {
		t.Error("Should have failed, not enough argument provided")
	}

}

func TestEnrollCLIWithCSR(t *testing.T) {

	c := new(cli.Config)

	args := []string{"notadmin", "pass", "http://localhost:8888", "../../testdata/csr.json"}

	err := enrollMain(args, *c)
	if err != nil {
		t.Error("Failed to enroll, err: ", err)
	}

}

func TestReenrollCLIWithCSR(t *testing.T) {

	c := new(cli.Config)

	args := []string{"http://localhost:8888", "../../testdata/csr.json"}

	err := reenrollMain(args, *c)
	if err != nil {
		t.Error("Failed to reenroll, err: ", err)
	}
}

func TestRevokeNoArg(t *testing.T) {

	c := new(cli.Config)

	args := []string{"http://localhost:8888"}

	err := revokeMain(args, *c)
	if err == nil {
		t.Error("TestRevokeNoArg succeeded but should have failed")
	}
}

func TestRevokeNotAdmin(t *testing.T) {

	c := new(cli.Config)

	args := []string{"http://localhost:8888", "admin"}

	err := revokeMain(args, *c)
	if err == nil {
		t.Error("TestRevokeNotAdmin should have failed but didn't")
	}

	os.RemoveAll(clientPath)
}

func TestBogusCommand(t *testing.T) {
	err := Command()
	if err == nil {
		t.Error("TestBogusCommand passed but should have failed")
	}
}

func runServer() {
	os.Setenv("COP_DEBUG", "true")
	server.Start("../../testdata")
}

func startServer() int {
	if _, err := os.Stat(clientPath); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(clientPath, 0755)
		}
	} else {
		os.RemoveAll(clientPath)
		os.MkdirAll(clientPath, 0755)
	}

	os.MkdirAll(filepath.Join(filepath.Join(clientPath, "ks"), "ks"), 0755)
	cpCmd := exec.Command("/bin/cp", "-Rf", KEYSTORE, clientPath)
	err := cpCmd.Run()
	if err != nil {
		panic(fmt.Errorf("Failed copying keystore [%s]", err.Error()))
	}

	if !serverStarted {
		serverStarted = true
		fmt.Println("starting COP server ...")
		os.Setenv("COP_HOME", clientPath)
		go runServer()
		time.Sleep(5 * time.Second)
		fmt.Println("COP server started")
	} else {
		fmt.Println("COP server already started")
	}
	return serverExitCode
}
