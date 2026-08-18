package main

import "C"
import (
	"fmt"
	"net"
	"os"

	"github.com/armon/go-socks5"
)

var server *socks5.Server
var listener net.Listener

func main() {
	username := os.Getenv("USERNAME")
	password := os.Getenv("PASSWORD")
	port := "3000"
	if username == "" {
		fmt.Println("USERNAME is empty")
		return
	}
	if password == "" {
		fmt.Println("PASSWORD is empty")
		return
	}
	creds := socks5.StaticCredentials{
		username: password,
	}
	auth := socks5.UserPassAuthenticator{
		Credentials: creds,
	}

	config := &socks5.Config{
		AuthMethods: []socks5.Authenticator{
			auth,
		},
	}
	var err error
	server, err = socks5.New(config)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	addr := ":" + port

	l, err := net.Listen("tcp", addr)
	listener = l

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	server.Serve(l)
}
