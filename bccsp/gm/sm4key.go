/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

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
package gm

import (
	"crypto/sha256"
	"errors"

	"github.com/hyperledger/fabric/bccsp"
)

type Gmsm4PrivateKey struct {
	PrivKey    []byte
	Exportable bool
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *Gmsm4PrivateKey) Bytes() ([]byte, error) {
	if k.Exportable {
		return k.PrivKey, nil
	}

	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *Gmsm4PrivateKey) SKI() []byte {
	hash := sha256.New()
	// hash := NewSM3()
	hash.Write([]byte{0x01})
	hash.Write(k.PrivKey)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *Gmsm4PrivateKey) Symmetric() bool {
	return true
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *Gmsm4PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *Gmsm4PrivateKey) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("Cannot call this method on a symmetric key.")
}
