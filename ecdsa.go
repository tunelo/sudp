package sudp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
)

const (
	SignatureSize = 64
)

func signMessage(privKey *ecdsa.PrivateKey, message []byte) ([64]byte, error) {
	var signature [64]byte

	hash := sha256.Sum256(message)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return signature, err
	}

	copy(signature[0:32], r.Bytes())
	copy(signature[32:64], s.Bytes())

	return signature, nil
}

func verifySignature(pubKey *ecdsa.PublicKey, message []byte, signature [64]byte) bool {
	hash := sha256.Sum256(message)

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	valid := ecdsa.Verify(pubKey, hash[:], r, s)
	return valid
}

func MarshalECDSAPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	// Marshal the private key into DER format
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	// Encode the DER data in PEM format
	block := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(&block), nil
}

// UnmarshalECDSAPrivateKey deserializes an ECDSA private key from PEM format
func UnmarshalECDSAPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing ECDSA private key")
	}

	// Parse the private key from the DER data
	return x509.ParseECPrivateKey(block.Bytes)
}

// MarshalECDSAPublicKey serializes an ECDSA public key into PEM format
func MarshalECDSAPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	// Marshal the public key into DER format (PKIX)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	// Encode the DER data in PEM format
	block := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(&block), nil
}

// UnmarshalECDSAPublicKey deserializes an ECDSA public key from PEM format
func UnmarshalECDSAPublicKey(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing ECDSA public key")
	}

	// Parse the public key from the DER data
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Assert the key to be of type ECDSA
	if pub, ok := pubKey.(*ecdsa.PublicKey); ok {
		return pub, nil
	}

	return nil, fmt.Errorf("not an ECDSA public key")
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func PrivateFromPemFile(file string) (*ecdsa.PrivateKey, error) {
	f, e := os.Open(file)
	if e != nil {
		return nil, e
	}
	b, e := io.ReadAll(f)
	return UnmarshalECDSAPrivateKey(b)
}

func PublicKeyFromPemFile(file string) (*ecdsa.PublicKey, error) {
	f, e := os.Open(file)
	if e != nil {
		return nil, e
	}
	b, e := io.ReadAll(f)
	return UnmarshalECDSAPublicKey(b)
}

func GeneratePEMKeyPair(private string, public string) error {
	pri, e := os.Create(private)
	if e != nil {
		return fmt.Errorf("creating private key: %v", e)
	}
	defer pri.Close()
	pub, e := os.Create(public)
	if e != nil {
		return fmt.Errorf("creating public key: %v", e)
	}
	defer pub.Close()

	pk, err := GenerateKey()
	if err != nil {
		return fmt.Errorf("generating private key: %v\n", err)
	}

	// Serialize the private and public keys
	prikey, err := MarshalECDSAPrivateKey(pk)
	if err != nil {
		return fmt.Errorf("serializing private key: %v\n", err)
	}

	pubkey, err := MarshalECDSAPublicKey(&pk.PublicKey)
	if err != nil {
		return fmt.Errorf("Error serializing public key: %v\n", err)
	}

	if _, err = pri.Write(prikey); err != nil {
		return fmt.Errorf("writing private key: %v", err)
	}
	if _, err = pub.Write(pubkey); err != nil {
		return fmt.Errorf("writing public key: %v", err)
	}
	return nil
}
