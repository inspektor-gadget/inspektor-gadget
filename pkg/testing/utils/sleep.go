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

package utils

import (
	"testing"
	"time"
)

type sleep struct {
	duration time.Duration
}

func Sleep(duraration time.Duration) *sleep {
	return &sleep{duration: duraration}
}

func (s *sleep) Run(t *testing.T) {
	time.Sleep(s.duration)
}

func (s *sleep) Start(t *testing.T) {
	t.Fatal("start not implemented for sleep cmd")
}

func (s *sleep) Stop(t *testing.T) {
	t.Fatal("stop not implemented for sleep cmd")
}

func (s *sleep) IsStartAndStop() bool {
	return false
}

func (s *sleep) Running() bool {
	return false
}
