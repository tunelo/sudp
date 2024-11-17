package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/tunelo/sudp"
)

var (
	defaultKeyType     = "string"
	baseVirtualAddress = 1000
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type SudpServerConfig struct {
	Filename string
	config   sudp.ServerConfig
}

type SudpClientConfig struct {
	Filename string
	config   sudp.ClientConfig
}

func randomString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func LoadSudpConfig(file string) (*SudpServerConfig, error) {
	config, err := sudp.LoadServerConfig(file)
	if err != nil {
		return nil, err
	}
	return &SudpServerConfig{config: *config, Filename: file}, nil
}

func NewSudpConfig(port int, public string) (*SudpServerConfig, error) {
	prikey, pubkey, err := sudp.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	listen := fmt.Sprintf("0.0.0.0:%d", port)
	config := sudp.ServerConfig{
		Attributes: &sudp.Attributes{
			PublicIP:   public,
			ListenPort: &port,
			PublicKey:  string(pubkey),
			KeyType:    &defaultKeyType,
		},
		Server: sudp.LocalConfig{
			VirtualAddress: 0,
			NetworkAddress: &listen,
			KeyType:        &defaultKeyType,
			PrivateKey:     string(prikey),
		},
		Peers: []sudp.RemoteConfig{},
	}
	return &SudpServerConfig{config: config}, nil
}

func (s *SudpServerConfig) Save() (string, error) {
	return s.Filename, s.config.DumpServerConfig(s.Filename)
}

func (s *SudpServerConfig) SaveAs(filename string) (string, error) {
	s.Filename = filename
	return s.Save()
}

func (s *SudpServerConfig) AddPeer() (*SudpClientConfig, error) {
	cpri, cpub, err := sudp.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	hmack := randomString(20)
	vaddr := len(s.config.Peers) + baseVirtualAddress

	s.config.Peers = append(s.config.Peers, sudp.RemoteConfig{
		VirtualAddress: vaddr,
		PublicKey:      string(cpub),
		SharedHmacKey:  &hmack,
		KeyType:        &defaultKeyType,
	})

	listen := fmt.Sprintf("%s:%d", s.config.Attributes.PublicIP, *s.config.Attributes.ListenPort)
	client := sudp.ClientConfig{
		Server: sudp.RemoteConfig{
			VirtualAddress: 0,
			PublicKey:      s.config.Attributes.PublicKey,
			NetworkAddress: &listen,
			SharedHmacKey:  &hmack,
			KeyType:        &defaultKeyType,
		},
		Host: sudp.LocalConfig{
			VirtualAddress: vaddr,
			KeyType:        &defaultKeyType,
			PrivateKey:     string(cpri),
		},
	}

	return &SudpClientConfig{config: client, Filename: fmt.Sprintf("%d_config.json", vaddr)}, nil
}

func (c *SudpClientConfig) Save() (string, error) {
	return c.Filename, c.config.DumpClientConfig(c.Filename)
}

func (c *SudpClientConfig) SaveAs(filename string) (string, error) {
	if !strings.HasSuffix(filename, ".json") {
		return "", fmt.Errorf("config file must ends with .json")
	}
	c.Filename = filename
	return c.Save()
}

func main() {
	var (
		new    bool
		add    bool
		server string
		client string
		public string
		port   int
		config *SudpServerConfig
		err    error
	)

	flag.BoolVar(&new, "new", false, "Create a new SUDP server configuration.")
	flag.BoolVar(&add, "add", false, "Add a new client to the SUDP server configuration file.")
	flag.StringVar(&server, "server", "", "Specify the server configuration file name to output")
	flag.StringVar(&client, "client", "", "Specify the client configuration file name to output.")
	flag.StringVar(&public, "public", "", "Set the public IP address of the server.")
	flag.IntVar(&port, "port", 7000, "Specify the server port. Default: 7000.")
	flag.Parse()

	if !add && !new {
		fmt.Println("command not found: add || new")
		os.Exit(1)
	}

	if server != "" {
		if !strings.HasSuffix(server, ".json") {
			fmt.Println("server filename must ends with .json")
			os.Exit(1)
		}
	}

	if client != "" {
		if !strings.HasSuffix(client, ".json") {
			fmt.Println("client filename must ends with .json")
			os.Exit(1)
		}
	}

	if new {
		if public == "" {
			fmt.Println("public is a mandatoty argument for new")
			os.Exit(1)
		}

		config, err = NewSudpConfig(port, public)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if server == "" {
			config.Filename = "server.json"
		} else {
			config.Filename = server
		}

	} else {
		if server == "" {
			fmt.Println("server config file is missing: -server <config name.json>")
			os.Exit(1)
		}
		config, err = LoadSudpConfig(server)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if add {
		var (
			name string
			err  error
		)
		peer, err := config.AddPeer()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if client != "" {
			name, err = peer.SaveAs(client)
		} else {
			name, err = peer.Save()
		}

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("client config created:", name)
	}

	name, err := config.Save()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if new {
		fmt.Println("server config created:", name)
	} else {
		fmt.Println("server config updated:", name)
	}
	os.Exit(0)
}
