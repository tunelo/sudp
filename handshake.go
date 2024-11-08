package sudp

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"time"
)

const handshakesz = 24 + 65 + 64

type handshake struct {
	hmac      [24]byte
	pubkey    [65]byte
	signature [64]byte
}

func (h handshake) String() string {
	return fmt.Sprintf(
		"Handshake{\n  hmac: %s,\n  PublicKey: %s,\n  Signature: %s\n}",
		hex.EncodeToString(h.hmac[:]),
		hex.EncodeToString(h.pubkey[:]),
		hex.EncodeToString(h.signature[:]),
	)
}

type pkthandshakeraw struct {
	hdr hdr
	hsk handshake
}

type handshakestate struct {
	tries    int
	senttime time.Time
	hdr      hdr
	msg      handshake
}

func (h *handshakestate) timeRetry(rtime int) bool {
	return time.Now().Sub(h.senttime) > time.Duration(rtime)*time.Second
}

func (h *handshakestate) repack(key *ecdsa.PrivateKey, hmkey []byte) (*pktbuff, error) {
	packet := allocPktbuff()
	h.hdr.hmac = [24]byte{}
	h.hdr.time = uint64(time.Now().UnixMicro())
	if err := h.hdr.dump(packet.tail(hdrsz), hmkey); err != nil {
		return nil, err
	}
	h.msg.signature = [64]byte{}
	h.msg.hmac = h.hdr.hmac
	if err := h.msg.dump(packet.tail(handshakesz), key); err != nil {
		return nil, err
	}
	h.senttime = time.Now()
	h.tries = h.tries + 1
	return packet, nil
}

func handshakeLoad(b []byte, v *ecdsa.PublicKey) (*handshake, error) {
	if len(b) < handshakesz {
		return nil, fmt.Errorf("invalid buffer size")
	}
	hs := handshake{}
	copy(hs.signature[:], b[24+65:handshakesz])
	if ok := verifySignature(v, b[0:24+65], hs.signature); !ok {
		return nil, fmt.Errorf("invalid signature")
	}
	copy(hs.hmac[:], b[0:24])
	copy(hs.pubkey[:], b[24:24+65])
	return &hs, nil
}

func (h *handshake) dump(b []byte, s *ecdsa.PrivateKey) error {
	var e error
	if len(b) < handshakesz {
		return fmt.Errorf("invalid buffer size")
	}
	copy(b[0:24], h.hmac[:])
	copy(b[24:24+65], h.pubkey[:])
	h.signature, e = signMessage(s, b[0:24+65])
	if e != nil {
		return e
	}
	copy(b[24+65:], h.signature[:])
	return nil
}

func (p *pkthandshakeraw) repack(key *ecdsa.PrivateKey, hmkey []byte) (*pktbuff, error) {
	packet := allocPktbuff()
	p.hdr.hmac = [24]byte{}
	p.hdr.time = uint64(time.Now().UnixMicro())
	if err := p.hdr.dump(packet.tail(hdrsz), hmkey); err != nil {
		return nil, err
	}
	p.hsk.signature = [64]byte{}
	p.hsk.hmac = p.hdr.hmac
	if err := p.hsk.dump(packet.tail(handshakesz), key); err != nil {
		return nil, err
	}
	return packet, nil
}
