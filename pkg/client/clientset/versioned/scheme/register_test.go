// Copyright 2019-2025 The Inspektor Gadget authors
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

package scheme

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestSchemeRegistration(t *testing.T) {
	// Test if Scheme is properly initialized
	if Scheme == nil {
		t.Error("Scheme should not be nil")
	}

	// Test if Codecs are properly initialized
	if Codecs.UniversalDeserializer() == nil {
		t.Error("Codecs should not have a nil universal deserializer")
	}

	// Test if ParameterCodec is properly initialized
	if ParameterCodec == nil {
		t.Error("ParameterCodec should not be nil")
	}
}

func TestAddToScheme(t *testing.T) {
	scheme := runtime.NewScheme()

	// Test adding types to scheme
	err := AddToScheme(scheme)
	if err != nil {
		t.Errorf("AddToScheme failed: %v", err)
	}

	// Verify that gadget types are registered
	gv := schema.GroupVersion{
		Group:   "gadget.kinvolk.io",
		Version: "v1alpha1",
	}

	// Check if the GroupVersion is registered
	if !scheme.IsVersionRegistered(gv) {
		t.Errorf("GroupVersion %v should be registered", gv)
	}
}

func TestSchemeDefaulters(t *testing.T) {
	scheme := runtime.NewScheme()

	err := AddToScheme(scheme)
	if err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}

	// Test if core v1 types are registered
	gv := schema.GroupVersion{Version: "v1"}
	if !scheme.IsVersionRegistered(gv) {
		t.Errorf("Core v1 version should be registered")
	}
}
