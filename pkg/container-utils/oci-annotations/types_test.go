// Copyright 2022 The Inspektor Gadget authors
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

package ociannotations

import (
	"reflect"
	"testing"
)

func TestNewResolver(t *testing.T) {
	tests := []struct {
		name    string
		runtime string
		want    string
		wantErr bool
	}{
		{
			name:    "get cri-o resolver",
			runtime: "cri-o",
			want:    "cri-o",
			wantErr: false,
		},
		{
			name:    "get containerd resolver",
			runtime: "containerd",
			want:    "containerd",
			wantErr: false,
		},
		{
			name:    "unsupported resolver",
			runtime: "unsupported",
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewResolver(tt.runtime)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewResolver() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(got.Runtime().String(), tt.want) {
				t.Errorf("NewResolverFromAnnotations().Runtime() got = %v, want %v", got.Runtime(), tt.want)
			}
		})
	}
}

func TestNewResolverFromAnnotations(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        string
		wantErr     bool
	}{
		{
			name:        "get cri-o resolver",
			annotations: map[string]string{crioContainerManagerAnnotation: "cri-o"},
			want:        "cri-o",
			wantErr:     false,
		},
		{
			name:        "get containerd resolver",
			annotations: map[string]string{containerdContainerTypeAnnotation: "test-container-type"},
			want:        "containerd",
			wantErr:     false,
		},
		{
			name:        "unsupported resolver",
			annotations: map[string]string{},
			want:        "",
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewResolverFromAnnotations(tt.annotations)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewResolverFromAnnotations() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(got.Runtime().String(), tt.want) {
				t.Errorf("NewResolverFromAnnotations().Runtime() got = %s, want %s", got.Runtime(), tt.want)
			}
		})
	}
}
