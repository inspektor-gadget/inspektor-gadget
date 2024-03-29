// Copyright 2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"math/rand"
	"strings"
	"time"
	"log"
)

const (
	controllerPathV2 = "/sys/fs/cgroup/cgroup.controllers"
	memoryLimit      = 512 * 1024 // 512 KiB
)

func hasMemoryCgroupV2() bool {
	_, err := os.Stat(controllerPathV2)
	if err != nil {
		return false
	}

	content, err := os.ReadFile(controllerPathV2)
	if err != nil {
		return false
	}

	return strings.Contains(string(content), "memory")
}

func writeFile(path string, content string) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	_, err = file.Write([]byte(content))
	file.Close()
	if err != nil {
		return err
	}

	return nil
}

func main() {
	seed := time.Now().UTC().UnixNano()
	r := rand.New(rand.NewSource(seed))

	log.Printf("using %d as seed", seed)

	cgroupName := fmt.Sprintf("oomkill-test-%d", r.Int31())
	var memoryMaxPath string
	var cgroupPath string
	var procsPath string

	if hasMemoryCgroupV2() {
		cgroupPath = filepath.Join("/sys", "fs", "cgroup", cgroupName)
		memoryMaxPath = filepath.Join(cgroupPath, "memory.max")
		procsPath = filepath.Join(cgroupPath, "cgroup.procs")
	} else {
		cgroupPath = filepath.Join("/sys", "fs", "cgroup", "memory", cgroupName)
		memoryMaxPath = filepath.Join(cgroupPath, "memory.limit_in_bytes")
		procsPath = filepath.Join(cgroupPath, "tasks")
	}

	err := os.Mkdir(cgroupPath, 0o755)
	if err != nil {
		log.Fatalf("creating %s: %v", cgroupPath, err)
	}
	defer syscall.Rmdir(cgroupPath)
	log.Printf("created cgroup %s under %s", cgroupName, cgroupPath)

	err = writeFile(memoryMaxPath, fmt.Sprintf("%d\n", memoryLimit))
	if err != nil {
		log.Fatalf("writing memory limit: %v", err)
	}
	log.Printf("set memory limit to %d", memoryLimit)

	time.Sleep(5 * time.Second)

	pid := os.Getpid()
	err = writeFile(procsPath, fmt.Sprintf("%d\n", pid))
	if err != nil {
		log.Fatalf("writing PID to proc file: %v", err)
	}
	log.Printf("added PID %d to cgroup", pid)

	for {
		// golang set to 0 everything, so it will touch this array and the memory
		// will effectively be allocated.
		// As the array is bigger than the limit, the OOM killer will be triggered
		// and this task will be killed.
		_ = make([]byte, memoryLimit << 1)
	}
}
