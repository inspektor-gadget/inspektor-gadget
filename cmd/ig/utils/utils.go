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
	"strconv"
	"fmt"
)

// WaitForEnd waits until the user-set timeout happened or SIGINT or SIGTERM
// is sent to us
func WaitForEnd(f *CommonFlags) {
	timeoutChannel := make(<-chan time.Time)
	if duration,err:= parseTimeout(f.Timeout);err==nil {
		timeoutChannel = time.After(duration)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-timeoutChannel:
	case <-stop:
	}
}

func parseTimeout(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
    if err == nil {
		return d, nil
    }
    sec, err := strconv.ParseInt(s, 10, 64)
    if err != nil {
        return 0, err
    }
    fmt.Printf("WARNING: The --timeout flag no longer accepts plain numeric values...")
    return time.Duration(sec) * time.Second, nil
}
