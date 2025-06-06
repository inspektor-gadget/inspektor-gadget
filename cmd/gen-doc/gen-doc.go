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
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/giantswarm/crd-docs-generator/pkg/annotations"
	"github.com/giantswarm/crd-docs-generator/pkg/config"
	"github.com/giantswarm/crd-docs-generator/pkg/crd"
	"github.com/giantswarm/crd-docs-generator/pkg/output"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
}

type GadgetOperation struct {
	Name  string
	Doc   string
	Order int
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

	for _, c := range getCrds() {
		exampleMap := make(map[string]string)
		for _, v := range c.Spec.Versions {
			version := v.Name

			example, err := os.ReadFile(filepath.Join(repo, fmt.Sprintf("pkg/resources/samples/%s_%s_%s.yaml", c.Spec.Group, version, c.Spec.Names.Singular)))
			if err != nil {
				panic(err)
			}

			exampleMap[version] = string(example)
		}

		var err error
		_, err = output.WritePage(
			c,
			[]annotations.CRDAnnotationSupport{},
			config.CRDItem{},
			exampleMap,
			filepath.Join(repo, "docs/crds"),
			"github.com/inspektor-gadget/inspektor-gadget",
			"version-unknown",
			filepath.Join(repo, "cmd/gen-doc/crd.template"))
		if err != nil {
			panic(err)
		}
	}
}
