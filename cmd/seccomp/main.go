package main

import (
	"fmt"
	"time"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/seccomp"
)

func main() {
	fmt.Printf("seccomp-gadget\n")
	advisor, err := seccomp.NewAdvisor()
	if err != nil {
		panic(err)
	}
	err = advisor.Start()
	if err != nil {
		panic(err)
	}

	for i := 0; i < 1000; i++ {
		time.Sleep(time.Second)
		fmt.Printf("Stamp\n")
	}
	advisor.Stop()

}
