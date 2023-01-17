// Copyright 2019-2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

const syscallsPath = `/sys/kernel/debug/tracing/events/syscalls/`

type param struct {
	position int
	name     string
}

type syscallDeclaration struct {
	name   string
	params []param
}

func syscallGetName(nr uint16) (string, error) {
	call := libseccomp.ScmpSyscall(nr)

	name, err := call.GetName()
	if err != nil {
		return "", fmt.Errorf("cannot get name of syscall number %d: %w", nr, err)
	}

	return name, nil
}

// TODO Find all syscalls which take a char * as argument and add them there.
var syscallDefs = map[string][6]uint64{
	"execve":      {useNullByteLength, 0, 0, 0, 0, 0},
	"access":      {useNullByteLength, 0, 0, 0, 0, 0},
	"open":        {useNullByteLength, 0, 0, 0, 0, 0},
	"openat":      {0, useNullByteLength, 0, 0, 0, 0},
	"mkdir":       {useNullByteLength, 0, 0, 0, 0, 0},
	"chdir":       {useNullByteLength, 0, 0, 0, 0, 0},
	"pivot_root":  {useNullByteLength, useNullByteLength, 0, 0, 0, 0},
	"mount":       {useNullByteLength, useNullByteLength, useNullByteLength, 0, 0, 0},
	"umount2":     {useNullByteLength, 0, 0, 0, 0, 0},
	"sethostname": {useNullByteLength, 0, 0, 0, 0, 0},
	"statfs":      {useNullByteLength, 0, 0, 0, 0, 0},
	"stat":        {useNullByteLength, 0, 0, 0, 0, 0},
	"statx":       {0, useNullByteLength, 0, 0, 0, 0},
	"lstat":       {useNullByteLength, 0, 0, 0, 0, 0},
	"fgetxattr":   {0, useNullByteLength, 0, 0, 0, 0},
	"lgetxattr":   {useNullByteLength, useNullByteLength, 0, 0, 0, 0},
	"getxattr":    {useNullByteLength, useNullByteLength, 0, 0, 0, 0},
	"newfstatat":  {0, useNullByteLength, 0, 0, 0, 0},
	"read":        {0, useRetAsParamLength | paramProbeAtExitMask, 0, 0, 0, 0},
	"write":       {0, useArgIndexAsParamLength + 2, 0, 0, 0, 0},
	"getcwd":      {useNullByteLength | paramProbeAtExitMask, 0, 0, 0, 0, 0},
	"pread64":     {0, useRetAsParamLength | paramProbeAtExitMask, 0, 0, 0, 0},
}

var re = regexp.MustCompile(`\s+field:(?P<type>.*?) (?P<name>[a-z_0-9]+);.*`)

func parseLine(l string, idx int) (*param, error) {
	n1 := re.SubexpNames()

	r := re.FindAllStringSubmatch(l, -1)
	if len(r) == 0 {
		return nil, nil
	}
	res := r[0]

	mp := map[string]string{}
	for i, n := range res {
		mp[n1[i]] = n
	}

	if _, ok := mp["type"]; !ok {
		return nil, nil
	}
	if _, ok := mp["name"]; !ok {
		return nil, nil
	}

	// ignore
	if mp["name"] == "__syscall_nr" {
		return nil, nil
	}

	var cParam param
	cParam.name = mp["name"]

	// The position is calculated based on the event format. The actual parameters
	// start from 8th index, hence we subtract that from idx to get position
	// of the parameter to the syscall
	cParam.position = idx - 8

	return &cParam, nil
}

// Map sys_enter_NAME to syscall name as in /usr/include/asm/unistd_64.h
// TODO Check if this is also true for arm64.
func relateSyscallName(name string) string {
	switch name {
	case "newfstat":
		return "fstat"
	case "newlstat":
		return "lstat"
	case "newstat":
		return "stat"
	case "newuname":
		return "uname"
	case "sendfile64":
		return "sendfile"
	case "sysctl":
		return "_sysctl"
	case "umount":
		return "umount2"
	default:
		return name
	}
}

func parseSyscall(name, format string) (*syscallDeclaration, error) {
	syscallParts := strings.Split(format, "\n")
	var skipped bool

	var cParams []param
	for idx, line := range syscallParts {
		if !skipped {
			if len(line) != 0 {
				continue
			} else {
				skipped = true
			}
		}
		cp, err := parseLine(line, idx)
		if err != nil {
			return nil, err
		}
		if cp != nil {
			cParams = append(cParams, *cp)
		}
	}

	return &syscallDeclaration{
		name:   name,
		params: cParams,
	}, nil
}

func gatherSyscallsDeclarations() (map[string]syscallDeclaration, error) {
	cSyscalls := make(map[string]syscallDeclaration)
	err := filepath.Walk(syscallsPath, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if path == "syscalls" {
			return nil
		}

		if !f.IsDir() {
			return nil
		}

		eventName := f.Name()
		if strings.HasPrefix(eventName, "sys_exit") {
			return nil
		}

		syscallName := strings.TrimPrefix(eventName, "sys_enter_")
		syscallName = relateSyscallName(syscallName)

		formatFilePath := filepath.Join(syscallsPath, eventName, "format")
		formatFile, err := os.Open(formatFilePath)
		if err != nil {
			return nil
		}
		defer formatFile.Close()

		formatBytes, err := io.ReadAll(formatFile)
		if err != nil {
			return err
		}

		cSyscall, err := parseSyscall(syscallName, string(formatBytes))
		if err != nil {
			return err
		}

		cSyscalls[cSyscall.name] = *cSyscall

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking %q: %w", syscallsPath, err)
	}
	return cSyscalls, nil
}

func getSyscallDeclaration(syscallsDeclarations map[string]syscallDeclaration, syscallName string) (syscallDeclaration, error) {
	declaration, ok := syscallsDeclarations[syscallName]
	if !ok {
		return syscallDeclaration{}, fmt.Errorf("no syscall correspond to %q", syscallName)
	}

	return declaration, nil
}

func (s syscallDeclaration) getParameterCount() uint8 {
	return uint8(len(s.params))
}

func (s syscallDeclaration) getParameterName(paramNumber uint8) (string, error) {
	if int(paramNumber) >= len(s.params) {
		return "", fmt.Errorf("param number %d out of bounds for syscall %q", paramNumber, s.name)
	}
	return s.params[paramNumber].name, nil
}
