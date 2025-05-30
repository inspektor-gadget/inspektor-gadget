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

package containercollection

import (
	"time"
)

type procOpts struct{}

func (procOpts) WithCPUUsage() bool         { return false }
func (procOpts) WithCPUUsageRelative() bool { return false }
func (procOpts) WithComm() bool             { return false }
func (procOpts) WithPPID() bool             { return true }
func (procOpts) WithState() bool            { return false }
func (procOpts) WithUID() bool              { return false }
func (procOpts) WithVmSize() bool           { return false }
func (procOpts) WithVmRSS() bool            { return false }
func (procOpts) WithMemoryRelative() bool   { return false }
func (procOpts) WithThreadCount() bool      { return false }
func (procOpts) WithStartTime() bool        { return false }

func (procOpts) TotalMemory() uint64              { return 0 }
func (procOpts) NumCPU() int                      { return 0 }
func (procOpts) LastCPUTime(_ int) (uint64, bool) { return 0, false }
func (procOpts) BootTime() time.Time              { return time.Time{} }
