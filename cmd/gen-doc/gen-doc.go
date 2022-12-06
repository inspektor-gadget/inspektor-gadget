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
	"os"
	"path/filepath"
	"sort"

	"github.com/giantswarm/crd-docs-generator/pkg/crd"
	"github.com/giantswarm/crd-docs-generator/pkg/metadata"
	"github.com/giantswarm/crd-docs-generator/pkg/output"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	gadgetcollection "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
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

func getCrds() (ret []apiextensionsv1.CustomResourceDefinition) {
	crdDir := filepath.Join(repo, "pkg/resources/crd/bases")
	crdFiles, err := os.ReadDir(crdDir)
	if err != nil {
		panic(err)
	}
	for _, crdFile := range crdFiles {
		crds, err := crd.Read(filepath.Join(crdDir, crdFile.Name()))
		if err != nil {
			panic(err)
		}
		ret = append(ret, crds...)
	}
	return ret
}

func main() {
	flag.Parse()

	funcMap := map[string]interface{}{}
	funcMap["include"] = func(input string) template.HTML {
		path := filepath.Join(repo, input)
		b, err := os.ReadFile(path)
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
		outputModesSet := gadget.Factory.OutputModesSupported()
		for k := range outputModesSet {
			gadget.OutputModes = append(gadget.OutputModes, string(k))
		}
		sort.Strings(gadget.OutputModes)

		for name, op := range gadget.Factory.Operations() {
			gadget.Operations = append(gadget.Operations, GadgetOperation{
				Name:  string(name),
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

		f, err := os.Create(filepath.Join(repo, "docs/crds/gadgets", gadget.Name+".md"))
		if err != nil {
			panic(err)
		}

		err = tpl.Execute(f, gadget)
		if err != nil {
			panic(err)
		}
	}

	for _, c := range getCrds() {
		err = output.WritePage(
			&c,
			[]output.CRDAnnotationSupport{},
			metadata.CRDItem{},
			filepath.Join(repo, "pkg/resources/samples"),
			filepath.Join(repo, "docs/crds"),
			"github.com/inspektor-gadget/inspektor-gadget",
			"version-unknown",
			filepath.Join(repo, "cmd/gen-doc/crd.template"))
		if err != nil {
			panic(err)
		}
	}
}
