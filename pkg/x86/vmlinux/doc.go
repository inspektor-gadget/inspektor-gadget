// Copyright 2019-2021 The Inspektor Gadget authors
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

// Package vmlinux does not provide any Go code but vmlinux.h to compile your
// BPF code. vmlinux was generated with the following command on
// Linux 5.12.6-300.fc34.x86_64:
// $ bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
package vmlinux
