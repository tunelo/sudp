package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sudp"
)

func main() {
	var (
		new    bool
		add    bool
		server string
		client string
		public string
		port   int
		config *sudp.ServerConfig
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
		fmt.Println("error: command not found: add || new")
		flag.Usage()
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

		config, err = sudp.NewServerConfig("0.0.0.", public, port)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if server == "" {
			server = "server.json"
		}

	} else {
		if server == "" {
			fmt.Println("server config file is missing: -server <config name.json>")
			os.Exit(1)
		}
		config, err = sudp.LoadServerConfig(server)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if add {
		var (
			err error
		)

		if client == "" {
			fmt.Println("mandatary argument is missing to add a new peer: -client <filename.json> ")
		}
		peer, err := config.AddPeer(sudp.AUTOINC)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = peer.DumpClientConfig(client)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("client config created:", client)
	}

	err = config.DumpServerConfig(server)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if new {
		fmt.Println("server config created:", server)
	} else {
		fmt.Println("server config updated:", server)
	}
	os.Exit(0)
}
