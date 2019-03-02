package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kinvolk/k8s-labels-to-bpf/pkg/pidmap"
)

func main() {
	fmt.Printf("Started\n")

	pm := pidmap.PidMap{}
	pm.Start()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
