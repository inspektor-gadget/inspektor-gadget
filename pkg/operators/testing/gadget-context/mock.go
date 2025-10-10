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

package gadgetcontext

import (
	"context"

	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// MockGadgetContext is a minimal mock implementation of operators.GadgetContext
type MockGadgetContext struct {
	Ctx         context.Context
	DataSources map[string]datasource.DataSource
	Log         logger.Logger
}

func (m *MockGadgetContext) ID() string {
	return "test-id"
}

func (m *MockGadgetContext) Name() string {
	return "test-gadget"
}

func (m *MockGadgetContext) Context() context.Context {
	return m.Ctx
}

func (m *MockGadgetContext) Logger() logger.Logger {
	if m.Log != nil {
		return m.Log
	}
	return logger.DefaultLogger()
}

func (m *MockGadgetContext) ExtraInfo() bool {
	return false
}

func (m *MockGadgetContext) Cancel() {}

func (m *MockGadgetContext) SerializeGadgetInfo(requestExtraInfo bool) (*api.GadgetInfo, error) {
	return nil, nil
}

func (m *MockGadgetContext) ImageName() string {
	return "test-image"
}

func (m *MockGadgetContext) RegisterDataSource(typ datasource.Type, name string) (datasource.DataSource, error) {
	return nil, nil
}

func (m *MockGadgetContext) GetDataSources() map[string]datasource.DataSource {
	return m.DataSources
}

func (m *MockGadgetContext) SetVar(key string, value any) {}

func (m *MockGadgetContext) GetVar(key string) (any, bool) {
	return nil, false
}

func (m *MockGadgetContext) Params() []*api.Param {
	return nil
}

func (m *MockGadgetContext) SetParams(params []*api.Param) {}

func (m *MockGadgetContext) SetMetadata(metadata []byte) error {
	return nil
}

func (m *MockGadgetContext) OrasTarget() oras.ReadOnlyTarget {
	return nil
}

func (m *MockGadgetContext) IsRemoteCall() bool {
	return false
}

func (m *MockGadgetContext) IsClient() bool {
	return false
}
