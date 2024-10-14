package sudp

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
)

const handshakesz = 4 + 65 + 64

type handshake struct {
	crc32     uint32
	pubkey    [65]byte
	signature [64]byte
}

func handshakeLoad(b []byte, v *ecdsa.PublicKey) (*handshake, error) {
	if len(b) < handshakesz {
		return nil, fmt.Errorf("invalid buffer size")
	}
	hs := handshake{}
	copy(hs.signature[:], b[4+65:handshakesz])
	if ok := verifySignature(v, b[0:4+65], hs.signature); !ok {
		return nil, fmt.Errorf("invalid signature")
	}
	hs.crc32 = binary.BigEndian.Uint32(b[0:4])
	copy(hs.pubkey[:], b[4:4+65])
	return &hs, nil
}

func (h *handshake) dump(b []byte, s *ecdsa.PrivateKey) error {
	var e error
	if len(b) < handshakesz {
		return fmt.Errorf("invalid buffer size")
	}
	binary.BigEndian.PutUint32(b[0:4], h.crc32)
	copy(b[4:4+65], h.pubkey[:])
	h.signature, e = signMessage(s, b[0:4+65])
	if e != nil {
		return e
	}
	copy(b[4+65:], h.signature[:])
	return nil
}
