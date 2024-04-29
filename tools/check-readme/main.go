// Copyright 2019-2024 The Inspektor Gadget authors
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
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
)

const (
	kubectlGadgetHelpLine = "$ kubectl gadget --help"
	threeDots             = "..."
)

func do() error {
	// Read all lines from the kubectl-gadget --help output
	var outb, errb bytes.Buffer
	cmd := exec.Command(os.Args[1], "--help")
	cmd.Stderr = &errb
	cmd.Stdout = &outb

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running: %w. stderr: %s", err, errb.String())
	}

	kubectlGadgetLines := strings.Split(outb.String(), "\n")

	file, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}

	// Read the whole readme and find where the $ kubectl gadget --help part is
	readmeLines := strings.Split(string(file), "\n")
	startIndex := slices.Index(readmeLines, kubectlGadgetHelpLine)
	if startIndex == -1 {
		return fmt.Errorf("finding %q", kubectlGadgetHelpLine)
	}
	endIndex := slices.Index(readmeLines[startIndex:], threeDots)
	if endIndex == -1 {
		return fmt.Errorf("finding %q", threeDots)
	}

	// Remove unuseful things
	readmeLines = readmeLines[startIndex+1 : startIndex+endIndex]
	if len(kubectlGadgetLines) < len(readmeLines) {
		return fmt.Errorf("kubectl-gadget output is shorter than README.md")
	}
	kubectlGadgetLines = kubectlGadgetLines[:len(readmeLines)]

	// Compare line by line. TODO: compare whole thing and print pretty diff?
	for i := 0; i < len(kubectlGadgetLines); i++ {
		if kubectlGadgetLines[i] != readmeLines[i] {
			return fmt.Errorf("line %d doesn't match: \n%q\n%q", i, kubectlGadgetLines[i], readmeLines[i])
		}
	}

	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <kubectl-gadget> <README.md>\n", os.Args[0])
		os.Exit(1)
	}

	if err := do(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
