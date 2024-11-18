package sudp

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
)

var (
	defaultKeyType = "string"
)

const (
	charset            = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	AUTOINC            = -1
	baseVirtualAddress = 1000
)

type LocalConfig struct {
	VirtualAddress int     `json:"virtual_address"`
	NetworkAddress *string `json:"network_address,omitempty"`
	KeyType        *string `json:"key_type,omitempty"`
	PrivateKey     string  `json:"private_key"`
}

type RemoteConfig struct {
	VirtualAddress int     `json:"virtual_address"`
	NetworkAddress *string `json:"network_address,omitempty"`
	SharedHmacKey  *string `json:"shared_hmac_key,omitempty"`
	KeyType        *string `json:"key_type,omitempty"`
	PublicKey      string  `json:"public_key"`
}

type Attributes struct {
	ListenPort *int    `json:"listen_port,omitempty"`
	PublicIP   string  `json:"public_ip"`
	PublicKey  string  `json:"public_key"`
	KeyType    *string `json:"key_type,omitempty"`
}

type ServerConfig struct {
	Attributes *Attributes    `json:"attributes,omitempty"`
	Server     LocalConfig    `json:"local"`
	Peers      []RemoteConfig `json:"peers"`
}

type ClientConfig struct {
	Server RemoteConfig `json:"server"`
	Host   LocalConfig  `json:"host"`
}

func (config *ClientConfig) LocalAddress() (*LocalAddr, error) {
	var (
		priv *ecdsa.PrivateKey
		addr *net.UDPAddr
		err  error
	)
	if config.Host.NetworkAddress != nil {
		addr, err = net.ResolveUDPAddr("udp4", *config.Host.NetworkAddress)
		if err != nil {
			return nil, err
		}
	}

	if config.Host.KeyType == nil || *config.Host.KeyType == "file" {
		priv, err = PrivateFromPemFile(config.Host.PrivateKey)
		if err != nil {
			return nil, err
		}
	} else if *config.Host.KeyType == "string" {
		priv, err = UnmarshalECDSAPrivateKey([]byte(config.Host.PrivateKey))
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid value in key_type")
	}

	laddr := LocalAddr{
		VirtualAddress: uint16(config.Host.VirtualAddress),
		NetworkAddress: addr,
		PrivateKey:     priv,
	}

	return &laddr, nil
}

func (config *ClientConfig) ServerAddress() (*RemoteAddr, error) {
	var (
		sharedHmac []byte
		pubk       *ecdsa.PublicKey
		err        error
	)

	if config.Server.NetworkAddress == nil {
		return nil, fmt.Errorf("mandatory field is missing server.network_address")
	}

	addr, e := net.ResolveUDPAddr("udp4", *config.Server.NetworkAddress)
	if e != nil {
		return nil, e
	}
	if config.Server.KeyType == nil || *config.Server.KeyType == "file" {
		pubk, err = PublicKeyFromPemFile(config.Server.PublicKey)
		if err != nil {
			return nil, err
		}
	} else if *config.Server.KeyType == "string" {
		pubk, err = UnmarshalECDSAPublicKey([]byte(config.Server.PublicKey))
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid value in key_type")
	}

	if config.Server.SharedHmacKey == nil {
		sharedHmac = nil
	} else {
		sharedHmac = []byte(*config.Server.SharedHmacKey)
	}

	raddr := &RemoteAddr{
		VirtualAddress: uint16(config.Server.VirtualAddress),
		NetworkAddress: addr,
		PublicKey:      pubk,
		SharedHmacKey:  sharedHmac,
	}
	return raddr, nil
}

func NewServerConfig(private string, public string, port int) (*ServerConfig, error) {
	prikey, pubkey, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	listen := fmt.Sprintf("%s:%d", private, port)
	config := ServerConfig{
		Attributes: &Attributes{
			PublicIP:   public,
			ListenPort: &port,
			PublicKey:  string(pubkey),
			KeyType:    &defaultKeyType,
		},
		Server: LocalConfig{
			VirtualAddress: 0,
			NetworkAddress: &listen,
			KeyType:        &defaultKeyType,
			PrivateKey:     string(prikey),
		},
		Peers: []RemoteConfig{},
	}
	return &config, nil
}

func (config *ServerConfig) AddPeer(vaddr int) (*ClientConfig, error) {
	cpri, cpub, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	rndstr := func(length int) string {
		result := make([]byte, length)
		for i := range result {
			result[i] = charset[rand.Intn(len(charset))]
		}
		return string(result)
	}

	hmack := rndstr(20)

	if vaddr == AUTOINC {
		vaddr = len(config.Peers) + baseVirtualAddress
	}

	config.Peers = append(config.Peers, RemoteConfig{
		VirtualAddress: vaddr,
		PublicKey:      string(cpub),
		SharedHmacKey:  &hmack,
		KeyType:        &defaultKeyType,
	})

	listen := fmt.Sprintf("%s:%d", config.Attributes.PublicIP, *config.Attributes.ListenPort)
	client := ClientConfig{
		Server: RemoteConfig{
			VirtualAddress: 0,
			PublicKey:      config.Attributes.PublicKey,
			NetworkAddress: &listen,
			SharedHmacKey:  &hmack,
			KeyType:        &defaultKeyType,
		},
		Host: LocalConfig{
			VirtualAddress: vaddr,
			KeyType:        &defaultKeyType,
			PrivateKey:     string(cpri),
		},
	}
	return &client, nil
}

func (config *ServerConfig) LocalAddress() (*LocalAddr, error) {
	var (
		priv *ecdsa.PrivateKey
		err  error
	)
	addr, e := net.ResolveUDPAddr("udp4", *config.Server.NetworkAddress)
	if e != nil {
		return nil, e
	}

	if config.Server.KeyType == nil || *config.Server.KeyType == "file" {
		priv, err = PrivateFromPemFile(config.Server.PrivateKey)
		if err != nil {
			return nil, err
		}
	} else if *config.Server.KeyType == "string" {
		priv, err = UnmarshalECDSAPrivateKey([]byte(config.Server.PrivateKey))
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid value in key_type")
	}

	laddr := LocalAddr{
		VirtualAddress: uint16(config.Server.VirtualAddress),
		NetworkAddress: addr,
		PrivateKey:     priv,
	}

	return &laddr, nil
}

func (config *ServerConfig) PeersAddresses() ([]*RemoteAddr, error) {
	raddr := []*RemoteAddr{}

	for _, peer := range config.Peers {
		var (
			sharedHmac []byte
			pubk       *ecdsa.PublicKey
			err        error
		)
		if peer.KeyType == nil || *peer.KeyType == "file" {
			pubk, err = PublicKeyFromPemFile(peer.PublicKey)
			if err != nil {
				return nil, err
			}
		} else if *peer.KeyType == "string" {
			pubk, err = UnmarshalECDSAPublicKey([]byte(peer.PublicKey))
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("invalid value in key_type")
		}

		if peer.SharedHmacKey == nil {
			sharedHmac = nil
		} else {
			sharedHmac = []byte(*peer.SharedHmacKey)
		}

		raddr = append(raddr, &RemoteAddr{
			VirtualAddress: uint16(peer.VirtualAddress),
			PublicKey:      pubk,
			SharedHmacKey:  sharedHmac,
		})
	}

	return raddr, nil
}

func LoadServerConfig(filePath string) (*ServerConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	config := &ServerConfig{}
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}
	return config, err
}

func LoadClientConfig(filePath string) (*ClientConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	config := &ClientConfig{}
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}
	return config, err
}

func (c *ClientConfig) DumpClientConfig(filePath string) error {
	content, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(content)
	return err
}

func (c *ServerConfig) DumpServerConfig(filePath string) error {
	content, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(content)
	return err
}
