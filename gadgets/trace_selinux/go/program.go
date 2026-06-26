// Copyright 2026 The Inspektor Gadget authors
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

// The WASM module post-processes SELinux AVC audit events emitted by the eBPF
// program. SELinux reports the requested/denied/audited permissions as
// access-vector bitmasks that are only meaningful relative to the target object
// class (tclass). This module decodes those bitmasks into human-readable
// permission names (e.g. "{ execute_no_trans }"), mirroring how denials appear
// in the kernel audit log.

package main

import (
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/trace_selinux/selinuxperms"
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// Must be >= TCLASS_LEN in program.bpf.c.
const tclassMaxSize = 64

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	ds, err := api.GetDataSource("selinux")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	tclassF, err := ds.GetField("tclass")
	if err != nil {
		api.Warnf("failed to get field tclass: %s", err)
		return 1
	}

	type permField struct {
		raw api.Field
		out api.Field
	}

	rawFields := []string{"denied", "requested", "audited"}
	permFields := make([]permField, 0, len(rawFields))
	for _, name := range rawFields {
		raw, err := ds.GetField(name)
		if err != nil {
			api.Warnf("failed to get field %s: %s", name, err)
			return 1
		}
		out, err := ds.AddField(name+"_perms", api.Kind_String)
		if err != nil {
			api.Warnf("failed to add field %s_perms: %s", name, err)
			return 1
		}
		permFields = append(permFields, permField{raw: raw, out: out})
	}

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		tclass, err := tclassF.String(data, tclassMaxSize)
		if err != nil {
			api.Warnf("failed to read tclass: %s", err)
			return
		}

		for _, pf := range permFields {
			mask, err := pf.raw.Uint32(data)
			if err != nil {
				api.Warnf("failed to read permission mask: %s", err)
				continue
			}
			pf.out.SetString(data, selinuxperms.Decode(tclass, mask))
		}
	}, 0)

	return 0
}

func main() {}
