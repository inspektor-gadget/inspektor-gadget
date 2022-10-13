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

package ellipsis_test

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
)

func ExampleShortenString() {
	fmt.Println(ellipsis.ShortenString("Foobar123", 8, ellipsis.None))
	fmt.Println(ellipsis.ShortenString("Foobar123", 8, ellipsis.Start))
	fmt.Println(ellipsis.ShortenString("Foobar123", 8, ellipsis.End))
	fmt.Println(ellipsis.ShortenString("Foobar123", 8, ellipsis.Middle))
	// Output:
	// Foobar12
	// …obar123
	// Foobar1…
	// Foob…123
}
