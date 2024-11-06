package sudp

import (
	"fmt"
)

type data struct {
	hmac [24]byte
	buff []byte
}

const (
	dataOverload  = 12 + 16 + 24
	DataHeaderLen = dataOverload
)

func (d *data) dump(cipher *dhss, dst []byte) error {
	if len(dst) < len(d.buff)+dataOverload {
		fmt.Errorf("dst to small to dump data")
	}
	// Push data
	copy(dst[24:], d.buff)
	copy(dst[0:24], d.hmac[:])
	c, e := cipher.encrypt(dst[0 : len(d.buff)+24])
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
		buff: d[24:],
	}
	copy(data.hmac[:], d[0:24])
	return &data, nil
}
