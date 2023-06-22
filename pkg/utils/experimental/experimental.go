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

package experimental

import (
	"os"
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/internal/deployinfo"
)

var (
	experimental bool
	once         sync.Once
)

const EnvName = "IG_EXPERIMENTAL"

func Enabled() bool {
	once.Do(func() {
		// Environment variable takes precedence
		if val, ok := os.LookupEnv(EnvName); ok {
			experimental = val == "true"
			return
		}

		info, err := deployinfo.Load()
		if err != nil {
			return
		}

		experimental = info.Experimental
	})

	return experimental
}
