package sudp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	DHPublicKeySize = 65
)

type dhss struct {
	curve  ecdh.Curve
	pk     *ecdh.PrivateKey
	shared []byte
}

type crypted struct {
	nonce []byte
	ctext []byte
}

func newCipher() (*dhss, error) {
	var (
		c dhss
		e error
	)
	c.curve = ecdh.P256()
	c.pk, e = c.curve.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	return &c, nil
}

func (c *dhss) public() []byte {
	return c.pk.PublicKey().Bytes()
}

func (c *dhss) ready() bool {
	return len(c.shared) != 0
}

func (c *dhss) ecdh(remote []byte) error {
	pb, e := c.curve.NewPublicKey(remote)
	if e != nil {
		return e
	}
	c.shared, e = c.pk.ECDH(pb)
	if e != nil {
		return e
	}
	return nil
}

func (c *dhss) encrypt(data []byte) (crypted, error) {
	block, err := aes.NewCipher(c.shared)
	if err != nil {
		return crypted{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return crypted{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return crypted{}, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return crypted{
		nonce: nonce,
		ctext: ciphertext,
	}, nil
}

func (c *dhss) decrypt(ctext *crypted) ([]byte, error) {
	block, err := aes.NewCipher(c.shared)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ctext.nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}
	plaintext, err := gcm.Open(nil, ctext.nonce, ctext.ctext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
