// Copyright 2024 The Inspektor Gadget authors
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

package api

import (
	"fmt"
)

//go:wasmimport env getContainers
func getContainers() uint32

//go:wasmimport env containerGetCgroupID
func containerGetCgroupID(c uint32) uint64

//go:wasmimport env containerGetMntns
func containerGetMntns(c uint32) uint64

type Container uint32

func GetContainers() Array {
	return Array(getContainers())
}

func (c Container) GetCgroupID() (uint64, error) {
	ret := containerGetCgroupID(uint32(c))
	if ret == 0 {
		return 0, fmt.Errorf("getting cgroup ID")
	}
	return ret, nil
}

func (c Container) GetMntNsID() (uint64, error) {
	ret := containerGetMntns(uint32(c))
	if ret == 0 {
		return 0, fmt.Errorf("getting mount namespace ID")
	}
	return ret, nil
}
