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

package main

//export init
func gadgetInit() {
	Log("hello from wasm")
	ds := GetDataSource("exec")
	ds2 := NewDataSource("foobydoo")
	ds2acc := ds2.AddField("wasm")
	comm := ds.GetField("comm")
	ds.Subscribe(func(source DataSource, data Data) {
		commstr := comm.String(data)
		Log("wasm got event")
		Log("comm is " + commstr)

		data2 := ds2.NewData()
		ds2acc.SetString(data2, "demo:"+commstr)
		ds2.EmitAndRelease(data2)
	}, 0)
}

//export preStart
func gadgetPreStart() {
}

//export start
func gadgetStart() {
}

//export stop
func gadgetStop() {
	Log("bye from wasm")
}

func main() {}
