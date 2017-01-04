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

package lib

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-cop/cli/server"
	"github.com/hyperledger/fabric-cop/idp"
)

const (
	CERT     string = "../testdata/ec.pem"
	KEY      string = "../testdata/ec-key.ski"
	CFG      string = "../testdata/cop.json"
	CSR      string = "../testdata/csr.json"
	REG      string = "../testdata/registerrequest.json"
	CONFIG   string = "../../testdata/cop.json"
	DBCONFIG string = "../testdata/enrolltest.json"
	HOME     string = "/tmp/client"
	KEYSTORE string = "../testdata/ks"
)

var serverStarted bool
var serverExitCode = 0

func prepTest() {
	_, err := os.Stat(HOME)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(HOME, 0755)
		}
	} else {
		os.RemoveAll(HOME)
		os.MkdirAll(HOME, 0755)
	}

	os.MkdirAll(filepath.Join(HOME, "ks"), 0755)
	cpCmd := exec.Command("/bin/cp", "-Rf", KEYSTORE, HOME)
	err = cpCmd.Run()
	if err != nil {
		panic(fmt.Errorf("Failed copying keystore [%s]", err.Error()))
	}
}

func TestAllClient(t *testing.T) {
	prepTest()
	startServer()
	c := getClient()

	testRegister(c, t)
	testRegisterWithoutRegistrar(c, t)
	testEnrollIncorrectPassword(c, t)
	testEnroll(c, t)
	testDoubleEnroll(c, t)
	testReenroll(c, t)
	testRevocation(c, t, "revoker", "revokerpw", true)
	testRevocation(c, t, "notadmin", "pass", false)
	testLoadCSRInfo(c, t)
	testLoadNoCSRInfo(c, t)
	testLoadBadCSRInfo(c, t)
	testCapabilities(c, t)
}

func testRegister(c *Client, t *testing.T) {

	// Enroll admin
	enrollReq := &idp.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	}

	id, err := c.Enroll(enrollReq)
	if err != nil {
		t.Errorf("testRegister enroll of admin failed: %s", err)
	}

	// Register as admin
	registerReq := &idp.RegistrationRequest{
		Name:      "TestUser",
		Type:      "Client",
		Group:     "bank_a",
		Registrar: id,
	}

	_, err = c.Register(registerReq)
	if err != nil {
		t.Errorf("Register failed: %s", err)
	}
}

func testRegisterWithoutRegistrar(c *Client, t *testing.T) {

	req := &idp.RegistrationRequest{
		Name: "TestUser",
		Type: "Client",
	}

	_, err := c.Register(req)
	if err == nil {
		t.Error("Register should have failed during registration without registrar")
	}
}

func testEnrollIncorrectPassword(c *Client, t *testing.T) {

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "incorrect",
	}

	_, err := c.Enroll(req)
	if err == nil {
		t.Error("Enroll with incorrect password passed but should have failed")
	}
}

func testEnroll(c *Client, t *testing.T) {

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	id, err := c.Enroll(req)
	if err != nil {
		t.Errorf("Enroll failed: %s", err)
	}

	err = id.Store()
	if err != nil {
		t.Errorf("testEnroll: store failed: %s", err)
	}

}

func testDoubleEnroll(c *Client, t *testing.T) {

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	_, err := c.Enroll(req)
	if err == nil {
		t.Error("Double enroll should have failed but passed")
	}

}

func testReenroll(c *Client, t *testing.T) {
	id, err := c.LoadMyIdentity()
	if err != nil {
		t.Errorf("testReenroll: failed LoadMyIdentity: %s", err)
		return
	}
	id, err = c.Reenroll(&idp.ReenrollmentRequest{ID: id})
	if err != nil {
		t.Errorf("testReenroll: failed reenroll: %s", err)
		return
	}
	err = id.Store()
	if err != nil {
		t.Errorf("testReenroll: failed Store: %s", err)
	}
}

func testRevocation(c *Client, t *testing.T, user, secret string, shouldPass bool) {
	req := &idp.EnrollmentRequest{
		Name:   user,
		Secret: secret,
	}
	id, err := c.Enroll(req)
	if err != nil {
		t.Errorf("enroll of user '%s' with password '%s' failed", user, secret)
		return
	}
	err = id.RevokeSelf()
	if shouldPass && err != nil {
		t.Errorf("testRevocation failed for user %s: %s", user, err)
	} else if !shouldPass && err == nil {
		t.Errorf("testRevocation for user %s passed but should have failed", user)
	}
}

func testLoadCSRInfo(c *Client, t *testing.T) {
	_, err := c.LoadCSRInfo("../testdata/csr.json")
	if err != nil {
		t.Errorf("testLoadCSRInfo failed: %s", err)
	}
}

func testLoadNoCSRInfo(c *Client, t *testing.T) {
	_, err := c.LoadCSRInfo("nofile")
	if err == nil {
		t.Error("testLoadNoCSRInfo passed but should have failed")
	}
}

func testLoadBadCSRInfo(c *Client, t *testing.T) {
	_, err := c.LoadCSRInfo("../testdata/config.json")
	if err == nil {
		t.Error("testLoadBadCSRInfo passed but should have failed")
	}
}

func testCapabilities(c *Client, t *testing.T) {
	caps := c.Capabilities()
	if caps == nil {
		t.Error("testCapabilities failed")
	}
}

func TestDeserializeIdentity(t *testing.T) {
	config := `{"serverURL":"http://localhost:8888"}`
	c, err := NewClient(config)
	if err != nil {
		t.Error("Failed to create client object")
	}

	idByte, err := ioutil.ReadFile("../testdata/client.json")
	if err != nil {
		t.Error("Error occured during reading of id file")
	}

	_, err = c.DeserializeIdentity(idByte)
	if err != nil {
		t.Error("Error occured during deserialization, error: ", err)
	}
}

func TestSendBadPost(t *testing.T) {
	c := new(Client)
	curl := "fake"
	reqBody := []byte("")
	req, _ := http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	_, err := c.SendPost(req)
	if err == nil {
		t.Error("Sending post should have failed")
	}
}

func getClient() *Client {
	copServer := `{"serverURL":"http://localhost:8888"}`
	c, err := NewClient(copServer)
	if err != nil {
		log.Errorf("getClient failed: %s", err)
	}
	return c
}

func startServer() int {
	if !serverStarted {
		serverStarted = true
		fmt.Println("starting COP server ...")
		os.Setenv("COP_HOME", HOME)
		go runServer()
		time.Sleep(3 * time.Second)
		fmt.Println("COP server started")
	} else {
		fmt.Println("COP server already started")
	}
	return serverExitCode
}

func runServer() {
	os.Setenv("COP_DEBUG", "true")
	os.Setenv("COP_HOME", HOME)
	server.Start("../testdata")
}
