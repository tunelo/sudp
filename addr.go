// SPDX-License-Identifier: GPL-3.0-or-later
//
// SUDP - Secure UDP Protocol Implementation
//
// Copyright (C) 2024 Emiliano A. Billi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package sudp

import (
	"crypto/ecdsa"
	"fmt"
	"net"
)

// RemoteAddr represents a remote peer's address and cryptographic information.
type RemoteAddr struct {
	VirtualAddress uint16           // Virtual address assigned to the remote peer.
	PublicKey      *ecdsa.PublicKey // The peer's public key for secure communication.
	SharedHmacKey  []byte           // Pre-shared HMAC key for message authentication.
	NetworkAddress *net.UDPAddr     // The peer's actual network address (IP and port).
}

// LocalAddr represents the local node's address and cryptographic information.
type LocalAddr struct {
	VirtualAddress uint16            // Virtual address assigned to the local node.
	PrivateKey     *ecdsa.PrivateKey // The local node's private key for secure communication.
	NetworkAddress *net.UDPAddr      // The local node's actual network address (IP and port).
}

// String returns a string representation of a RemoteAddr instance.
func (a *RemoteAddr) String() string {
	pkok := a.PublicKey != nil
	hmok := a.SharedHmacKey != nil
	return fmt.Sprintf("remote: %s,%d - Public Key: %t - Header Hmac: %t", a.NetworkAddress.String(), a.VirtualAddress, pkok, hmok)
}

// String returns a string representation of a LocalAddr instance.
func (a *LocalAddr) String() string {
	ok := a.PrivateKey != nil
	if a.NetworkAddress == nil {
		return fmt.Sprintf("local: %s,%d - Private Key: %t", "0.0.0.0:0", a.VirtualAddress, ok)
	}
	return fmt.Sprintf("local: %s,%d - Private Key: %t", a.NetworkAddress.String(), a.VirtualAddress, ok)
}
