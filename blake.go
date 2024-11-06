package sudp

import "golang.org/x/crypto/blake2b"

func Blake192Hmac(b []byte, key []byte) [24]byte {
	var sum [24]byte
	h, _ := blake2b.New(24, key)
	h.Write(b)
	copy(sum[:], h.Sum(nil))
	return sum
}
