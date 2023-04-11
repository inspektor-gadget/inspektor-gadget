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
	"bufio"
	_ "embed"
	"flag"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

type DropReasonT struct {
	ID            int
	Name          string
	Documentation string
}

//go:embed dropreason.h
var dropReasonHeader string

//go:embed dropreason.md.tmpl
var dropReasonMdTemplate string

// flags
var outputFlag = flag.String("output", "", "output file")

func DropReasons() (ret map[int]DropReasonT) {
	ret = make(map[int]DropReasonT)

	s := bufio.NewScanner(strings.NewReader(dropReasonHeader))

	enumFound := false
	currentIndex := -1
	currentName := ""
	currentDocumentation := ""

	for s.Scan() {
		line := s.Text()

		if !enumFound {
			if line == "enum skb_drop_reason {" {
				enumFound = true
			}
			continue
		}

		// First line of comment
		re := regexp.MustCompile(`\* @([A-Z0-9_]*): (.*)`)
		matches := re.FindAllStringSubmatch(line, 1)
		if len(matches) == 1 {
			currentIndex++
			currentName = matches[0][1]
			currentDocumentation = matches[0][2]
			currentDocumentation = strings.TrimSuffix(currentDocumentation, " */")

			ret[currentIndex] = DropReasonT{
				ID:            currentIndex,
				Name:          currentName,
				Documentation: currentDocumentation,
			}
			continue
		}

		// Next lines of comment
		re = regexp.MustCompile(`\* (.*)`)
		matches = re.FindAllStringSubmatch(line, 1)
		if len(matches) == 1 && currentIndex >= 0 {
			currentDocumentation += " " + matches[0][1]
			ret[currentIndex] = DropReasonT{
				ID:            currentIndex,
				Name:          currentName,
				Documentation: currentDocumentation,
			}
		}

		// End of enum
		if line == "};" {
			break
		}
	}
	return ret
}

func main() {
	flag.Parse()

	drMap := DropReasons()
	dr := []DropReasonT{}
	for _, v := range drMap {
		dr = append(dr, v)
	}
	sort.Slice(dr, func(i, j int) bool {
		return dr[i].ID < dr[j].ID
	})

	tmpl, err := template.New("dropreason.tmpl").Parse(dropReasonMdTemplate)
	if err != nil {
		panic(err)
	}
	// Execute template to save it to file
	var f *os.File
	if *outputFlag == "" {
		f = os.Stdout
	} else {
		f, err = os.Create(*outputFlag)
		if err != nil {
			panic(err)
		}
	}

	err = tmpl.Execute(f, dr)
	if err != nil {
		panic(err)
	}
}
