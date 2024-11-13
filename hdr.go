package sudp

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	hdrsz     = 20
	HeaderLen = hdrsz
)

type hdr struct {
	ver   uint8
	kind  uint8
	len   uint16
	src   uint16
	dst   uint16
	epoch uint32
	time  uint64
	hmac  [24]byte
}

func newHdr(kind uint8, epoch uint32, src, dst uint16) *hdr {
	h := hdr{
		ver:   protocolVersion,
		kind:  kind,
		epoch: epoch,
		src:   src,
		dst:   dst,
		time:  uint64(time.Now().UnixMicro()),
	}
	return &h
}

func hdrSrcDst(b []byte) (uint16, uint16) {
	return binary.BigEndian.Uint16(b[4:]), binary.BigEndian.Uint16(b[6:])
}

func hdrLoad(b []byte, hmkey []byte) (*hdr, error) {
	if len(b) < hdrsz {
		return nil, fmt.Errorf("invalid buffer size")
	}
	crc := Blake192Hmac(b, hmkey) //hmac.ChecksumIEEE(b)
	h := &hdr{
		ver:   b[0],
		kind:  b[1],
		len:   binary.BigEndian.Uint16(b[2:]),
		src:   binary.BigEndian.Uint16(b[4:]),
		dst:   binary.BigEndian.Uint16(b[6:]),
		epoch: binary.BigEndian.Uint32(b[8:]),
		time:  binary.BigEndian.Uint64(b[12:]),
		hmac:  crc,
	}
	if h.ver != protocolVersion {
		return nil, fmt.Errorf("invalid protocol")
	}
	if h.kind != typeClientHandshake &&
		h.kind != typeServerHandshake &&
		h.kind != typeCtrlMessage &&
		h.kind != typeData {
		return nil, fmt.Errorf("invalid message")
	}
	return h, nil
}

func (h *hdr) dump(b []byte, hmkey []byte) error {
	if b == nil || len(b) < hdrsz {
		return fmt.Errorf("invalid buffer size")
	}
	b[0] = h.ver
	b[1] = h.kind
	binary.BigEndian.PutUint16(b[2:], h.len)
	binary.BigEndian.PutUint16(b[4:], h.src)
	binary.BigEndian.PutUint16(b[6:], h.dst)
	binary.BigEndian.PutUint32(b[8:], h.epoch)
	binary.BigEndian.PutUint64(b[12:], h.time)
	h.hmac = Blake192Hmac(b[:hdrsz], hmkey) //crc32.ChecksumIEEE(b[:hdrsz])
	return nil
}

func (h *hdr) String() string {
	return fmt.Sprintf("Version: %d, Kind: %d, Length: %d, Source: %d, Destination: %d, Epoch: %d, Time: %d, hmac: 0x%08x",
		h.ver, h.kind, h.len, h.src, h.dst, h.epoch, h.time, h.hmac)
}
