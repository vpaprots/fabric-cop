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
	"crypto"
	"encoding/pem"
	"fmt"

	"io/ioutil"
	"time"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/cloudflare/cfssl/signer/universal"
	"github.com/hyperledger/fabric/core/crypto/bccsp"
	bccspsigner "github.com/hyperledger/fabric/core/crypto/bccsp/signer"
)

var pemType = "BCCSP SKI"

// PEMKeyToSKI imports PEM key into BCCSP key store and stores out to a file
func PEMKeyToSKI(csp bccsp.BCCSP, path, skiPath string) error {
	keyBuff, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Cannot get Private Key [%s]", err.Error())
	}
	block, _ := pem.Decode(keyBuff)

	k, err := csp.KeyImport(block.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: false})
	if err != nil {
		return fmt.Errorf("CA Private Key Object cannot be generated [%s]", err.Error())
	}

	skiEncoded := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: k.SKI()})
	err = ioutil.WriteFile(skiPath, skiEncoded, 0644)
	if err != nil {
		return fmt.Errorf("Cannot write Private Key SKI [%s]", err.Error())
	}
	return nil
}

func getSignerFromSKI(ski []byte) (crypto.Signer, error) {
	privateKey, err := CFG.csp.GetKey(ski)
	if err != nil {
		return nil, err
	}

	signer := &bccspsigner.CryptoSigner{}
	if err = signer.Init(CFG.csp, privateKey); err != nil {
		return nil, err
	}
	return signer, nil
}

func getSignerFromSKIFile(skiFile string) (crypto.Signer, error) {
	keyBuff, err := ioutil.ReadFile(skiFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBuff)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding file [%s]", skiFile)
	}

	if block.Type != pemType {
		return nil, fmt.Errorf("Decoded PEM type does not match expected: [%s] got: [%s]", pemType, block.Type)
	}

	return getSignerFromSKI(block.Bytes)
}

// bccspBackedSigner determines whether a file-backed local signer is supported.
func bccspBackedSigner(root *universal.Root, policy *config.Signing) (signer.Signer, bool, error) {
	skiFile := root.Config["key-file"]
	caFile := root.Config["cert-file"]

	if skiFile == "" {
		return nil, false, nil
	}

	if caFile == "" {
		return nil, false, nil
	}

	log.Debug("Loading CA for SKI: ", caFile)
	ca, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, false, err
	}

	parsedCa, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, false, err
	}

	caPrivateKey, err := getSignerFromSKIFile(skiFile)
	if err != nil {
		log.Debug("Failed to load %s: %s", skiFile, err)
		return nil, false, err
	}

	signer, err := local.NewSigner(caPrivateKey, parsedCa, signer.DefaultSigAlgo(caPrivateKey), policy)
	return signer, true, err
}

// SignerFromConfig creates a signer from a cli.Config as a helper for cli and serve
func ocspSignerFromConfig(c cli.Config) (ocsp.Signer, error) {
	//if this is called from serve then we need to use the specific responder key file
	//fallback to key for backwards-compatibility
	k := c.ResponderKeyFile
	if k == "" {
		k = c.KeyFile
	}
	key, err := getSignerFromSKIFile(k)
	if err != nil {
		return nil, err
	}

	return ocsp.NewSignerFromFileAndKey(c.CAFile, c.ResponderFile, key, time.Duration(c.Interval))
}
