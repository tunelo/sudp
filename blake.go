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

import "golang.org/x/crypto/blake2b"

func blake192Hmac(b []byte, key []byte) [24]byte {
	var sum [24]byte
	h, _ := blake2b.New(24, key)
	h.Write(b)
	copy(sum[:], h.Sum(nil))
	return sum
}
