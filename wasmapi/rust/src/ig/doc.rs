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

/*
Package api contains the reference implementation of the wasm API for Inspektor
Gadget. It's designed to be used by gadgets and not by any other internal
component of Inspektor Gadget.
*/

/*
A similar function to runtime.keepAlive() in 'Golang' is not required in
rust due to ownership model as the variable don't go out of scope until
block lifetime.
*/
