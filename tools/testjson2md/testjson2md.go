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
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/medyagh/gopogh/pkg/models"
	"github.com/medyagh/gopogh/pkg/parser"
	"github.com/medyagh/gopogh/pkg/report"
)

var ErrInvalidContent = fmt.Errorf("invalid content")

var (
	inPath        = flag.String("in", "", "path to JSON file produced by go tool test2json")
	outPath       = flag.String("out", "", "path to output file")
	truncateLines = flag.Int("truncate-lines", 50, "number of failed test log lines to truncate to")
)

func main() {
	flag.Parse()

	if *inPath == "" {
		log.Fatal("must provide path to JSON input file")
	}

	if *outPath == "" {
		log.Fatal("must provide path to output file")
	}

	events, err := parser.ParseJSON(*inPath)
	if err != nil {
		log.Fatal(err)
	}
	groups := parser.ProcessEvents(events)
	content, err := report.Generate(models.ReportDetail{}, groups)
	if err != nil {
		log.Fatal(err)
	}

	markdown, err := markdownForContent(content)
	if err != nil {
		log.Fatal(err)
	}

	if err = os.WriteFile(*outPath, markdown, 0644); err != nil {
		log.Fatal(err)
	}
}

func markdownForContent(content report.DisplayContent) ([]byte, error) {
	// validation
	if _, ok := content.Results["pass"]; !ok {
		return nil, fmt.Errorf("checking passed tests: %w", ErrInvalidContent)
	}
	if _, ok := content.Results["skip"]; !ok {
		return nil, fmt.Errorf("checking skip tests: %w", ErrInvalidContent)
	}
	if _, ok := content.Results["fail"]; !ok {
		return nil, fmt.Errorf("checking failed tests: %w", ErrInvalidContent)
	}

	// set report status
	reportStatus := ":green_circle:"
	if len(content.Results["fail"]) > 0 {
		reportStatus = ":red_circle:"
	}

	// summary
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "### Test Report %s\n", reportStatus)
	fmt.Fprintf(&buf, "#### Summary\n")
	fmt.Fprintf(&buf, "| Total Tests | Passed :heavy_check_mark: | Failed :x: | Skipped :arrow_right_hook: |\n")
	fmt.Fprintf(&buf, "| ----- | ---- | ---- | ---- |\n")
	fmt.Fprintf(&buf, "| %d | %d | %d | %d |\n", content.TotalTests,
		len(content.Results["pass"]), len(content.Results["fail"]), len(content.Results["skip"]))

	// failed tests
	if len(content.Results["fail"]) > 0 {
		fmt.Fprintf(&buf, "#### Failed Tests\n")
		for _, test := range content.Results["fail"] {
			fmt.Fprintf(&buf, "<details><summary>%s</summary>\n\n", test.TestName)
			fmt.Fprintf(&buf, "```code\n")
			fmt.Fprintf(&buf, "%s", testEventToString(lastN(test.Events, *truncateLines)))
			fmt.Fprintf(&buf, "```\n")
			fmt.Fprintf(&buf, "</details>\n")
		}
		fmt.Fprintf(&buf, "\n")
	}

	// test durations
	fmt.Fprintf(&buf, "#### Test Durations :stopwatch:\n")
	appendDuration(content, &buf, "Passed", "pass")
	appendDuration(content, &buf, "Failed", "fail")
	appendDuration(content, &buf, "Skipped", "skip")

	return buf.Bytes(), nil
}

func appendDuration(content report.DisplayContent, buf *bytes.Buffer, title, status string) {
	if len(content.Results[status]) == 0 {
		return
	}
	fmt.Fprintf(buf, "<details><summary>%s</summary>\n\n", title)
	fmt.Fprintf(buf, "| Duration | Test | Run Order |\n")
	fmt.Fprintf(buf, "| -------- | ---- | --------- |\n")
	for _, test := range sortTestGroups(content.Results[status]) {
		fmt.Fprintf(buf, "| %s | %s | %d |\n", time.Duration(test.Duration*float64(time.Second)), test.TestName, test.TestOrder)
	}
	fmt.Fprintf(buf, "</details>\n")
}

func sortTestGroups(groups []models.TestGroup) []models.TestGroup {
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Duration > groups[j].Duration
	})
	return groups
}

func testEventToString(events []models.TestEvent) string {
	var buf bytes.Buffer
	for _, event := range events {
		fmt.Fprintf(&buf, "%s", event.Output)
	}
	return buf.String()
}

func lastN[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
