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

package utils

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

// WaitForEnd waits until the user-set timeout happened or SIGINT or SIGTERM
// is sent to us
func WaitForEnd(f *CommonFlags) {
	timeoutChannel := make(<-chan time.Time)
	if f.Timeout != 0 {
		timeoutChannel = time.After(time.Duration(f.Timeout) * time.Second)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-timeoutChannel:
	case <-stop:
	}
}
