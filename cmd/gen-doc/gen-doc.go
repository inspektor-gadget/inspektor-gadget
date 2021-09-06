// Copyright 2021 The Inspektor Gadget authors
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
	_ "embed"
	"flag"
	"html/template"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/kinvolk/inspektor-gadget/pkg/gadget-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
)

var repo string

func init() {
	flag.StringVar(&repo, "repo", "", "path to the repository")
}

type GadgetData struct {
	Name        string
	Description string
	OutputModes []string
	Operations  []GadgetOperation
	Factory     gadgets.TraceFactory
}

type GadgetOperation struct {
	Name  string
	Doc   string
	Order int
}

//go:embed gadget.template
var gadgetTemplate string

func getTraceFactories() (ret []GadgetData) {
	for name, factory := range gadgetcollection.TraceFactories() {
		ret = append(ret, GadgetData{
			Name:        name,
			Description: factory.(gadgets.TraceFactoryWithDocumentation).Description(),
			Factory:     factory,
		})
	}
	return ret
}

func main() {
	flag.Parse()

	funcMap := map[string]interface{}{}
	funcMap["include"] = func(input string) template.HTML {
		path := filepath.Join(repo, input)
		b, err := ioutil.ReadFile(path)
		if err != nil {
			return template.HTML(err.Error())
		}
		return template.HTML(string(b))
	}
	funcMap["raw"] = func(input string) template.HTML {
		return template.HTML(input)
	}

	tpl, err := template.New("gadget.template").Funcs(funcMap).Parse(gadgetTemplate)
	if err != nil {
		panic(err)
	}

	for _, gadget := range getTraceFactories() {
		if factoryWithCaps, ok := gadget.Factory.(gadgets.TraceFactoryWithCapabilities); ok {
			outputModesSet := factoryWithCaps.OutputModesSupported()
			for k := range outputModesSet {
				gadget.OutputModes = append(gadget.OutputModes, k)
			}
			sort.Strings(gadget.OutputModes)
		} else {
			gadget.OutputModes = []string{"Status"}
		}
		for name, op := range gadget.Factory.Operations() {
			gadget.Operations = append(gadget.Operations, GadgetOperation{
				Name:  name,
				Doc:   op.Doc,
				Order: op.Order,
			})
		}
		sort.Slice(gadget.Operations, func(i, j int) bool {
			oi, oj := gadget.Operations[i], gadget.Operations[j]
			switch {
			case oi.Order != oj.Order:
				return oi.Order < oj.Order
			default:
				return oi.Name < oj.Name
			}
		})

		f, err := os.Create(filepath.Join(repo, "docs/gadgets", gadget.Name+".md"))
		if err != nil {
			panic(err)
		}

		err = tpl.Execute(f, gadget)
		if err != nil {
			panic(err)
		}
	}
}
