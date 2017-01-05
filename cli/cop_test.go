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

import "testing"

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
