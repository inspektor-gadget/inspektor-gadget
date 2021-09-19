package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

/*
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

int my_pipefd[2];
int my_pipefd_reply[2];

void my_sig_handler(int sig) {
	write(my_pipefd[1], "X", 1);
	char buf;
	read(my_pipefd_reply[0], &buf, 1);
}

void init_sig_handler() {
	if (pipe(my_pipefd) == -1) { // TODO: use pipe2() with O_CLOEXEC
	    perror("pipe2");
	    exit(1);
	}
	if (pipe(my_pipefd_reply) == -1) { // TODO: use pipe2() with O_CLOEXEC
	    perror("pipe2");
	    exit(1);
	}

	struct sigaction sa = {};
	sa.sa_flags = SA_ONSTACK;
	sa.sa_handler = my_sig_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGILL, &sa, NULL) == -1) {
	    perror("sigaction");
	    exit(1);
	}
}
*/
import "C"

func init() {
	C.init_sig_handler()
	go func() {
		for {
			buf := make([]byte, 1<<20)
			var p [1]byte
			_, _ = unix.Read(int(C.my_pipefd[0]), p[:])
			stacklen := runtime.Stack(buf, true)
			fmt.Printf("%s\n", buf[:stacklen])
			_, _ = unix.Write(int(C.my_pipefd_reply[1]), []byte{0})
		}
	}()

}

func main() {
	go func() {
		file, err := os.Open("/dev/null")
		if err != nil {
			panic(err)
		}
		content, err := ioutil.ReadAll(file)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", string(content))
		runtime.GC()
	}()
	time.Sleep(time.Second)
	_, _ = ioutil.ReadFile("/dev/null")
}
