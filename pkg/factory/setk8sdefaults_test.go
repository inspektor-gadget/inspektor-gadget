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

package factory

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

func TestSetKubernetesDefaults(t *testing.T) {
	t.Run("sets default GroupVersion", func(t *testing.T) {
		config := &rest.Config{}
		err := SetKubernetesDefaults(config)
		require.NoError(t, err)
		require.NotNil(t, config.GroupVersion)
		require.Equal(t, schema.GroupVersion{Group: "", Version: "v1"}, *config.GroupVersion)
	})

	t.Run("sets default APIPath", func(t *testing.T) {
		config := &rest.Config{}
		err := SetKubernetesDefaults(config)
		require.NoError(t, err)
		require.Equal(t, "/api", config.APIPath)
	})

	t.Run("does not override existing APIPath", func(t *testing.T) {
		config := &rest.Config{APIPath: "/custom"}
		err := SetKubernetesDefaults(config)
		require.NoError(t, err)
		require.Equal(t, "/custom", config.APIPath)
	})

	t.Run("sets default NegotiatedSerializer", func(t *testing.T) {
		config := &rest.Config{}
		err := SetKubernetesDefaults(config)
		require.NoError(t, err)
		require.NotNil(t, config.NegotiatedSerializer)

		expectedSerializer := &serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs}
		require.Equal(t, expectedSerializer, config.NegotiatedSerializer)
	})

	t.Run("does not override existing NegotiatedSerializer", func(t *testing.T) {
		config := &rest.Config{}
		customSerializer := &serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs}
		config.NegotiatedSerializer = customSerializer

		err := SetKubernetesDefaults(config)
		require.NoError(t, err)
		require.NotNil(t, config.NegotiatedSerializer)
		require.Same(t, customSerializer, config.NegotiatedSerializer)
	})
}
