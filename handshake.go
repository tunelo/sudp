package sudp

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

const handshakesz = 4 + 65 + 64

type handshake struct {
	crc32     uint32
	pubkey    [65]byte
	signature [64]byte
}

func (h handshake) String() string {
	return fmt.Sprintf(
		"Handshake{\n  CRC32: %08x,\n  PublicKey: %s,\n  Signature: %s\n}",
		h.crc32,
		hex.EncodeToString(h.pubkey[:]),
		hex.EncodeToString(h.signature[:]),
	)
}

type pkthandshakeraw struct {
	hdr hdr
	hsk handshake
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

func (p *pkthandshakeraw) repack(key *ecdsa.PrivateKey) (*pktbuff, error) {
	packet := allocPktbuff()
	p.hdr.crc32 = 0
	p.hdr.time = uint64(time.Now().UnixMilli())
	if err := p.hdr.dump(packet.tail(hdrsz)); err != nil {
		return nil, err
	}
	p.hsk.signature = [64]byte{}
	p.hsk.crc32 = p.hdr.crc32
	if err := p.hsk.dump(packet.tail(handshakesz), key); err != nil {
		return nil, err
	}
	fmt.Println(p.hdr.String(), p.hsk.String())
	return packet, nil
}
