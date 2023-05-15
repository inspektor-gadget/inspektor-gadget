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

package common

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func TestHandleFileArguments(t *testing.T) {
	t.Parallel()

	pd := &params.ParamDesc{
		Key:      "test",
		TypeHint: "string",
	}
	p := Param{
		Param: pd.ToParam(),
	}

	const fileContent = "This is a magic String. 123$$##@!"
	const filename = "./file_param_testfile"
	require.Nil(t, os.WriteFile(filename, []byte(fileContent), 0o600))
	defer os.Remove(filename)

	err := p.Set(FilePrefix + filename)
	require.Nil(t, err, "Error while handling file argument")
	require.Equal(t, p.AsString(), fileContent)
}
