package sudp

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
)

const ctrlmessagesz = 4 + 4 + 8 + 64

const (
	KeepAlive    uint32 = 1 << 0 // Bit 0
	RTT          uint32 = 1 << 1 // Bit 1
	KeepAliveAck uint32 = 1 << 2 // Bit 2
	EpochAck     uint32 = 1 << 3 // Bit 3
)

type ctrlmessage struct {
	crc32     uint32
	ctrl      uint32
	data      uint64
	signature [64]byte
}

func ctrlmessageLoad(b []byte, v *ecdsa.PublicKey) (*ctrlmessage, error) {

	if len(b) < ctrlmessagesz {
		return nil, fmt.Errorf("invalid buffer size")
	}
	c := ctrlmessage{}
	copy(c.signature[:], b[16:16+64])
	if ok := verifySignature(v, b[0:16], c.signature); !ok {
		return nil, fmt.Errorf("invalid signature")
	}
	c.crc32 = binary.BigEndian.Uint32(b[0:4])
	c.ctrl = binary.BigEndian.Uint32(b[4:8])
	c.data = binary.BigEndian.Uint64(b[8:16])
	return &c, nil
}

func (c *ctrlmessage) set(flag uint32) {
	c.ctrl |= flag
}

func (c *ctrlmessage) isSet(flag uint32) bool {
	return c.ctrl&flag != 0
}

func (c *ctrlmessage) dump(b []byte, s *ecdsa.PrivateKey) error {
	var e error
	if len(b) < ctrlmessagesz {
		return fmt.Errorf("invalid buffer size")
	}
	binary.BigEndian.PutUint32(b[0:4], c.crc32)
	binary.BigEndian.PutUint32(b[4:8], c.ctrl)
	binary.BigEndian.PutUint64(b[8:16], c.data)
	c.signature, e = signMessage(s, b[0:16])
	if e != nil {
		return e
	}
	copy(b[16:], c.signature[:])
	return nil
}
