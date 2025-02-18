// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpfoperator

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"oras.land/oras-go/v2"
)

type mockGadget struct{}

func (m *mockGadget) ID() string                     { return "" }
func (m *mockGadget) GadgetDesc() gadgets.GadgetDesc { return nil }

func (m *mockGadget) GadgetDataSource() gadgets.GadgetDesc { return nil }

func (m *mockGadget) Logger() logger.Logger { return nil }

func (m *mockGadget) SerializeGadgetInfo() (*api.GadgetInfo, error) { return nil, nil }

func (m *mockGadget) SetVar(name string, value interface{}) {}

func (m *mockGadget) Cancel() {}

func (m *mockGadget) Deadline() (deadline time.Time, ok bool) { return time.Time{}, false }

func (m *mockGadget) Err() error { return nil }

func (m *mockGadget) Value(key interface{}) interface{} { return nil }

func (m *mockGadget) Context() context.Context { return nil }

func (m *mockGadget) GetDataSources() map[string]datasource.DataSource { return nil }

func (m *mockGadget) GetVar(string) (any, bool) { return "", false }

func (m *mockGadget) ImageName() string { return "" }

func (m *mockGadget) IsRemoteCall() bool { return false }

func (m *mockGadget) OrasTarget() oras.ReadOnlyTarget { return nil }

func (m *mockGadget) Params() []*api.Param { return nil }

func (m *mockGadget) SetParams([]*api.Param) {}

func (m *mockGadget) RegisterDataSource(datasource.Type, string) (datasource.DataSource, error) {
	return nil, nil
}

func (m *mockGadget) SetMetadata([]byte) {}
func TestPopulateVar(t *testing.T) {
	tests := []struct {
		name        string
		inputType   btf.Type
		varName     string
		expectErr   error
		expectedVar *ebpfVar
	}{
		{
			name: "returns error when not a btf.var",
			inputType: &btf.Var{
				Name: "int32",
				Type: &btf.Const{
					Type: &btf.Volatile{
						Type: &btf.Int{
							Name: "int32", Size: 4,
						},
					},
				},
			},
			varName:   "valid_var",
			expectErr: nil,
			expectedVar: &ebpfVar{
				tags: []string{"int32"},
			},
		},
		{
			name: "returns float32",
			inputType: &btf.Var{
				Name: "float32",
				Type: &btf.Const{
					Type: &btf.Volatile{
						Type: &btf.Float{
							Name: "float32", Size: 4,
						},
					},
				},
			},
			varName:   "valid_var",
			expectErr: nil,
			expectedVar: &ebpfVar{
				tags: []string{"float32"},
			},
		},
		{
			name: "return int but empty",
			inputType: &btf.Var{
				Type: &btf.Const{
					Type: &btf.Volatile{
						Type: &btf.Int{},
					},
				},
			},
			varName:   "valid_var",
			expectErr: nil,
			expectedVar: &ebpfVar{
				tags: []string{},
			},
		},
		{
			name:      "Failure - Not a btf.Var",
			inputType: &btf.Int{},
			varName:   "not_a_var",
			expectErr: errors.New("\"not_a_var\" not of type *btf.Var"),
		},
		{
			name: "Failure - Not a btf.Const",
			inputType: &btf.Var{
				Type: &btf.Int{},
			},
			varName:   "not_a_const",
			expectErr: errors.New("\"not_a_const\" not a const"),
		},
		{
			name: "Failure - Not a btf.Volatile",
			inputType: &btf.Var{
				Type: &btf.Const{
					Type: &btf.Int{},
				},
			},
			varName:   "not_volatile",
			expectErr: errors.New("\"not_volatile\" not volatile"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			logger.Out = io.Discard
			instance := &ebpfInstance{
				vars:      make(map[string]*ebpfVar),
				gadgetCtx: &mockGadget{},
				logger:    logger,
			}
			err := instance.populateVar(tt.inputType, tt.varName)

			if res, ok := instance.vars[tt.varName]; ok {
				assert.Equal(t, tt.expectedVar.tags, res.tags)
			}
			assert.Equal(t, err, tt.expectErr)
		})
	}
}
