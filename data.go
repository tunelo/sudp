package sudp

import (
	"encoding/binary"
	"fmt"
)

type data struct {
	crc32 uint32
	buff  []byte
}

const (
	dataOverload  = 12 + 16 + 4
	DataHeaderLen = dataOverload
)

func (d *data) dump(cipher *dhss, dst []byte) error {
	if len(dst) < len(d.buff)+dataOverload {
		fmt.Errorf("dst to small to dump data")
	}
	// Push data
	copy(dst[4:], d.buff)
	binary.BigEndian.PutUint32(dst[0:4], d.crc32)
	c, e := cipher.encrypt(dst[0 : len(d.buff)+4])
	if e != nil {
		return e
	}
	copy(dst[0:12], c.nonce)
	copy(dst[12:], c.ctext)
	return nil
}

func (d *data) size() uint16 {
	return uint16(len(d.buff) + dataOverload)
}

func loadData(b []byte, cipher *dhss) (*data, error) {
	if cipher == nil {
		return nil, fmt.Errorf("nil key")
	}
	d, e := cipher.decrypt(&crypted{
		nonce: b[0:12],
		ctext: b[12:],
	})
	if e != nil {
		return nil, e
	}
	data := data{
		crc32: binary.BigEndian.Uint32(d[0:4]),
		buff:  d[4:],
	}
	return &data, nil
}
