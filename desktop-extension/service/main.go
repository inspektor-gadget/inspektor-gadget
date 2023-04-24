package main

import (
	"flag"
	"net"
	"net/http"
)

func main() {
	var socketPath = flag.String("socket", "/run/guest-services/ig-desktop-extension.sock", "Unix domain socket to listen on")
	flag.Parse()

	root := "/"
	server := http.Server{
		Handler: http.FileServer(http.Dir(root)),
	}

	unixListener, err := net.Listen("unix", *socketPath)
	if err != nil {
		panic(err)
	}
	server.Serve(unixListener)
}
