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

package main

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <stddef.h>

// Function pointer types for the library functions
typedef void (*print_hello_world_func)(void);
typedef void (*sleep_one_second_func)(void);
typedef void (*busy_loop_500ms_func)(void);
typedef void* (*allocate_memory_func)(size_t);

// Wrapper functions to call the function pointers
static void call_print_hello_world(void* fn) {
    ((print_hello_world_func)fn)();
}

static void call_sleep_one_second(void* fn) {
    ((sleep_one_second_func)fn)();
}

static void call_busy_loop_500ms(void* fn) {
    ((busy_loop_500ms_func)fn)();
}

static void* call_allocate_memory(void* fn, size_t size) {
    return ((allocate_memory_func)fn)(size);
}
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"
)

var (
	printHelloWorld unsafe.Pointer
	sleepOneSecond  unsafe.Pointer
	busyLoop500ms   unsafe.Pointer
	allocateMemory  unsafe.Pointer
)

func loadLibrary() {
	// Get the directory of the executable
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get executable path: %v\n", err)
		os.Exit(1)
	}
	libPath := filepath.Join(filepath.Dir(execPath), "libmylib.so")

	cLibPath := C.CString(libPath)
	defer C.free(unsafe.Pointer(cLibPath))

	handle := C.dlopen(cLibPath, C.RTLD_LAZY)
	if handle == nil {
		errMsg := C.dlerror()
		fmt.Fprintf(os.Stderr, "dlopen failed: %s\n", C.GoString(errMsg))
		os.Exit(1)
	}

	// Load function pointers
	printHelloWorld = loadSymbol(handle, "print_hello_world")
	sleepOneSecond = loadSymbol(handle, "sleep_one_second")
	busyLoop500ms = loadSymbol(handle, "busy_loop_500ms")
	allocateMemory = loadSymbol(handle, "allocate_memory")
}

func loadSymbol(handle unsafe.Pointer, name string) unsafe.Pointer {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	sym := C.dlsym(handle, cName)
	if sym == nil {
		errMsg := C.dlerror()
		fmt.Fprintf(os.Stderr, "dlsym failed for %s: %s\n", name, C.GoString(errMsg))
		os.Exit(1)
	}
	return sym
}

func eat_apple() {
	for i := 0; i < 2; i++ {
		C.call_allocate_memory(allocateMemory, 64)
	}
}

func eat_banana() {
	for i := 0; i < 2; i++ {
		C.call_allocate_memory(allocateMemory, 512)
	}
}

func eat_orange() {
	for i := 0; i < 2; i++ {
		C.call_allocate_memory(allocateMemory, 1024)
	}
}

func pick_up_fruits() {
	eat_apple()
	eat_banana()
	eat_orange()
	C.call_sleep_one_second(sleepOneSecond)
	C.call_sleep_one_second(sleepOneSecond)
	os.Exit(0)
}

func my_garden() {
	pick_up_fruits()
	pick_up_fruits()
}

func main() {
	fmt.Printf("Go version: %s\n", runtime.Version())

	fmt.Println("Press Enter to start the workload...")
	fmt.Scanln()

	loadLibrary()

	C.call_print_hello_world(printHelloWorld)
	C.call_allocate_memory(allocateMemory, 8)
	C.call_sleep_one_second(sleepOneSecond)
	C.call_sleep_one_second(sleepOneSecond)
	C.call_busy_loop_500ms(busyLoop500ms)

	my_garden()
	time.Sleep(1 * time.Second)
}
