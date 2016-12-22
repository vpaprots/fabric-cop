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

package server

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric/core/crypto/bccsp"
	"github.com/hyperledger/fabric/core/crypto/bccsp/signer"
)

var initUsageText = `cop server init CSRJSON -- generates a new private key and self-signed certificate
Usage:
        cop server init CSRJSON
Arguments:
        CSRJSON:    JSON file containing the request, use '-' for reading JSON from stdin
Flags:
`

var initFlags = []string{"remote", "u"}

// Generate generates a key as specified in the request. Currently,
// only ECDSA and RSA are supported.
func getBCCSPKeyOpts(kr csr.KeyRequest, ephemeral bool) (opts bccsp.KeyGenOpts, err error) {
	if kr == nil {
		return &bccsp.ECDSAKeyGenOpts{Temporary: false}, nil
	}
	log.Debugf("generate key from request: algo=%s, size=%d", kr.Algo(), kr.Size())
	switch kr.Algo() {
	case "rsa":
		switch kr.Size() {
		case 2048:
			return &bccsp.RSA2048KeyGenOpts{Temporary: ephemeral}, nil
		case 3072:
			return &bccsp.RSA3072KeyGenOpts{Temporary: ephemeral}, nil
		case 4096:
			return &bccsp.RSA4096KeyGenOpts{Temporary: ephemeral}, nil
		default:
			if kr.Size() < 2048 {
				return nil, errors.New("RSA key is too weak")
			}
			if kr.Size() > 8192 {
				return nil, errors.New("RSA key size too large")
			}
			// Need to add a way to specify arbitrary RSA key size to bccsp
			return nil, errors.New("unsupported RSA key size")
		}
	case "ecdsa":
		switch kr.Size() {
		case 256:
			return &bccsp.ECDSAP256KeyGenOpts{Temporary: ephemeral}, nil
		case 384:
			return &bccsp.ECDSAP384KeyGenOpts{Temporary: ephemeral}, nil
		case 521:
			// Need to add curve P521 to bccsp
			// return &bccsp.ECDSAP512KeyGenOpts{Temporary: false}, nil
			return nil, errors.New("unsupported curve")
		default:
			return nil, errors.New("invalid curve")
		}
	default:
		return nil, errors.New("invalid algorithm")
	}
}

// initMain creates the private key and self-signed certificate needed to start COP Server
func initMain(args []string, c cli.Config) (err error) {
	csrFile, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return errors.New(err.Error())
	}

	csrFileBytes, err := cli.ReadStdin(csrFile)
	if err != nil {
		return errors.New(err.Error())
	}

	req := csr.CertificateRequest{
		KeyRequest: csr.NewBasicKeyRequest(),
	}
	err = json.Unmarshal(csrFileBytes, &req)
	if err != nil {
		return errors.New(err.Error())
	}

	configInit(&c)
	COPHome := CFG.Home
	csp := CFG.csp

	log.Infof("generating key: %s-%d", req.KeyRequest.Algo(), req.KeyRequest.Size())
	keyOpts, err := getBCCSPKeyOpts(req.KeyRequest, false)
	if err != nil {
		return errors.New(err.Error())
	}

	key, err := csp.KeyGen(keyOpts)
	if err != nil {
		return errors.New(err.Error())
	}

	signer := &signer.CryptoSigner{}
	err = signer.Init(csp, key)
	if err != nil {
		return fmt.Errorf("Failed initializing CyrptoSigner [%s]", err)
	}

	c.IsCA = true

	var cert []byte
	cert, _, err = initca.NewFromSigner(&req, signer)
	if err != nil {
		return errors.New(err.Error())
	}

	if err != nil {
		return errors.New(err.Error())
	}
	certerr := ioutil.WriteFile(COPHome+"/server-cert.pem", cert, 0755)
	if certerr != nil {
		log.Fatal("Error writing server-cert.pem to $COPHome directory")
	}

	skiEncoded := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: key.SKI()})
	keyerr := ioutil.WriteFile(COPHome+"/server-key.ski", skiEncoded, 0755)
	if keyerr != nil {
		log.Fatal("Error writing server-key.pem to $COPHome directory")
	}

	return nil
}

// InitServerCommand assembles the definition of Command 'genkey -initca CSRJSON'
var InitServerCommand = &cli.Command{UsageText: initUsageText, Flags: initFlags, Main: initMain}
