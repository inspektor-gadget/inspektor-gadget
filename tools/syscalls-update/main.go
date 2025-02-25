// Copyright 2025 The Inspektor Gadget authors
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
	_ "embed"
	"encoding/csv"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"mvdan.cc/gofumpt/format"
)

//go:embed syscalls_arch.go.tmpl
var syscallsTemplate string

const (
	sourceURL = "https://raw.githubusercontent.com/seccomp/libseccomp/refs/heads/main/src/syscalls.csv"

	nameColumnIndex = 0
)

type Syscall struct {
	Name string
	Nr   int
}

type TemplateData struct {
	Source     string
	Arch       string
	ColumnName string
	OutputFile string

	KernelVersion string
	Syscalls      []Syscall
	ColumnIndex   int
}

var allTemplateData = map[string]*TemplateData{
	"amd64": {
		Arch:       "amd64",
		ColumnName: "x86_64",
		OutputFile: "../../pkg/utils/syscalls/syscalls_amd64.go",
	},
	"arm64": {
		Arch:       "arm64",
		ColumnName: "aarch64",
		OutputFile: "../../pkg/utils/syscalls/syscalls_arm64.go",
	},
}

func main() {
	resp, err := http.Get(sourceURL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	reader := csv.NewReader(resp.Body)
	header, err := reader.Read()
	if err != nil {
		log.Fatal(err)
	}
	if len(header) == 0 {
		log.Fatal("Empty header")
	}

	kernelVersion := header[nameColumnIndex]
	kernelVersion = strings.TrimPrefix(kernelVersion, "#syscall (")
	kernelVersion = strings.TrimSuffix(kernelVersion, ")")
	for _, tmplData := range allTemplateData {
		tmplData.KernelVersion = kernelVersion
		tmplData.Source = sourceURL
	}
	for _, tmplData := range allTemplateData {
		for i, column := range header {
			if column == tmplData.ColumnName {
				tmplData.ColumnIndex = i
				break
			}
		}
	}

	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		name := record[nameColumnIndex]

		for _, tmplData := range allTemplateData {
			nrStr := record[tmplData.ColumnIndex]
			// kernel version undefined or pseudo syscall
			if nrStr == "KV_UNDEF" || nrStr == "PNR" {
				continue
			}
			nr, err := strconv.Atoi(nrStr)
			if err != nil {
				log.Printf("Skipping syscall %q: %s", name, err)
				continue
			}
			tmplData.Syscalls = append(tmplData.Syscalls, Syscall{Name: name, Nr: nr})
		}
	}

	tmpl, err := template.New("syscalls_arch.go.tmpl").Parse(syscallsTemplate)
	if err != nil {
		log.Fatal(err)
	}

	for _, tmplData := range allTemplateData {
		sort.Slice(tmplData.Syscalls, func(i, j int) bool {
			return tmplData.Syscalls[i].Name < tmplData.Syscalls[j].Name
		})

		file, err := os.Create(tmplData.OutputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		buf := new(bytes.Buffer)
		err = tmpl.Execute(buf, tmplData)
		if err != nil {
			log.Fatalf("Error executing template: %v", err)
		}
		out, err := format.Source(buf.Bytes(), format.Options{})
		if err != nil {
			log.Fatalf("Error formatting source: %v", err)
		}
		_, err = file.Write(out)
		if err != nil {
			log.Fatalf("Error writing to file: %v", err)
		}
	}
}
