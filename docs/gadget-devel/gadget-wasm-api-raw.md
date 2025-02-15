---
title: 'Wasm API'
sidebar_position: 420
description: 'Wasm API for other programming languages'
---

Inspektor Gadget exposes some functions to wasm modules implemented in gadgets.
We provide a [Golang](./gadget-wasm-api-go.md) wrapper for this functionality,
but these functions can be used directly from any programming language that can
be compiled to wasm.

## Data types

Data types passed to the API are encoded using 64 bits. Scalar types like
integers, booleans and floats are casted directly to 64 bit integers and passed
using the stack.

Strings and byte arrays are stored in the wasm module's memory as `bufPtr`. A 64
bit integer is used to represent a pointer to them, the higher 32 bits contains
the length and the lower 32 the memory address.

## Wasm Module Exported Functions

The Wasm module implemented by the gadget also needs to export some functions to
be invoked by the host.

### `gadgetAPIVersion`

This function is used by Inspektor Gadget to check that the version of the API
used by the wasm module is compatible. The function doesn't receive any
parameter and must return an 64 bit integer. If the version doesn't match
exactly the one expected by Inspektor Gadget, the initialization of the gadget
fails. Currently only version 1 is supported and used. This function is mandatory.

### `gadgetInit`

This function is called when initializing the gadget. In this phase the gadget
can subscribe to data sources, create new fields, etc. This function is optional.

### `gadgetPreStart`

This function is called before the gadget is started. This function is optional.

### `gadgetStart`

This function is called when the gadget is started. This function is optional.

### `gadgetStop`

This function is called when the gadget is stopped. It's used to clean up
things. This function is optional.

### `gadgetPostStop`

This function is called after the the gadget is stopped. This function is optional.

#### `malloc`

The gadget should expose a `malloc` function that allocates memory on the heap
of the wasm module. This is needed by the host to allocate memory to pass
strings and byte arrays around. This function is automatically exported when
using tinygo https://github.com/tinygo-org/tinygo/issues/2788.

TODO: We'll check this requirement later on.

#### `dataSourceCallback`

See description in dataSourceSubscribe below.

## API

### Log

#### `gadgetLog(u32 level, string msg)`

Print a log message using the gadget's logger instance.

Parameters:

- `level` (u32): Log level:
  - 0: Error
  - 1: Warn
  - 2: Info
  - 3: Debug
  - 4: Trace
- `msg` (string): Message to print

Return value:
- None

### Datasources

#### `newDataSource(string name)`

Creates a new data source.

Parameters:
- `name` (string): Data source name

Return value:
- (u32): Handle to the created data source on success, 0 on error.

#### `getDataSource(string name) u32`

Get a handle to a data source.

Parameters:
- `name` (string): Datasource's name

Return value:
- (u32) Handle to the data source on success, 0 on error.

#### `dataSourceSubscribe(u32 ds, u32 type, u32 prio, u64 cb)`

Subscribe to events emitted by a data source.

This mechanism requires the wasm module to export a `dataSourceCallback` that is called
by the host when an event is emitted:

`dataSourceCallback(u64 cbID, u32 ds, u32 data)`
- `cbID`: Callback ID
- `ds`: Datasource handle
- `data`: Depending on the subscription type, it can be a Data, DataArray or
  Packet handle.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `type` (u32): Subscription type: (0: Data, 1: Array, 2: Packet)
- `priority` (u32): Priority of the subscription. The lower the value the higher the priority.
- `cb` (u64): Opaque ID that is passed back to `dataSourceCallback` to identify the subscription.

Return value:
- 0 on success, 1 in case of error.

#### `dataSourceGetField(u32 ds, string name) u32`

Get a field from a datasource

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `name`(string): Field's name

Return value:
- (u32): Field handle on success, 0 on error.

#### `dataSourceAddField(u32 ds, string name, u32 kind) u32`

Add a field to a data source

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `name`(string): Field's name
- `kind` (u32): Field's kind. See values in https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget@main/pkg/gadget-service/api#Kind.

Return value:
- (u32): Field handle on success, 0 on error.

#### `dataSourceNewPacketSingle(u32 ds) u32`

Allocate a packet instance. The returned packet has to be released with
`dataSourceEmitAndRelease` or `dataSourceRelease`.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)

Return value:
- (u32): On error, it returns 0. Otherwise, the returned value can be used as a
  Data or Packet handle.

#### `dataSourceNewPacketArray(u32 ds) u32`

Allocate a packet array instance. The returned packet has to be released with
`dataSourceEmitAndRelease` or `dataSourceRelease`. Depending on the context, get
or allocate elements in the array with `dataArrayGet` or `dataArrayNew` +
`dataArrayAppend`. Then use the returned Data handle to get or set the field
values.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)

Return value:
- (u32): On error, it returns 0. Otherwise, the returned value can be used as a
  DataArray or Packet handle.

#### `dataSourceEmitAndRelease(u32 ds, u32 packet) u32`

Emit and release a packet instance.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `packet` (u32): Packet handle (as returned by `dataSourceNewPacketSingle` or `dataSourceNewPacketArray`)

Return value:
- 0 in case of success, 1 otherwise.

#### `dataSourceRelease(u32 ds, u32 packet)`

Release a packet instance without sending it.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `packet` (u32): Packet handle (as returned by `dataSourceNewPacketSingle` or
  `dataSourceNewPacketArray`)

Return value:
- None

#### `dataSourceUnreference(u32 ds)`

Unreference a data source from further operators.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)

Return value:
- None

#### `dataSourceIsReferenced(u32 ds)`

Check if the data source is referenced.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)

Return value:
- (u32): Boolean value on success (0 or 1), 2 on error

#### `dataArrayNew(d uint32) uint32`

Allocate and return a new element on the array. If the whole DataArray is not
released with `dataSourceEmitAndRelease` or `dataSourceRelease`, the returned
element has to be released with `dataArrayRelease`.

Parameters:
- `d` (u32): DataArray handle

Return value:
- (u32): Data handle on success, 0 on error

#### `dataArrayAppend(d uint32, data uint32)`

Append data to the array. As a side-effect, the data handle is released and it shouldn't be used after this call.

Parameters:
- `d` (u32): DataArray handle
- `data` (u32): Data handle to append

Return value:
- None

#### `dataArrayRelease(d uint32, data uint32)`

Releases the memory of Data; Data may not be used after calling this.

Parameters:
- `d` (u32): DataArray handle
- `data` (u32): Data handle to release

Return value:
- None

#### `dataArrayLen(d uint32) uint32`

Get the number of elements in the array.

Parameters:
- `d` (u32): DataArray handle
-
Return value:
- (u32): Number of elements in the array

#### `dataArrayGet(d uint32, index uint32) uint32`

Get the element at the given index.

Parameters:
- `d` (u32): DataArray handle
- `index` (u32): Data index. Max index is 32767

Return value:
- (u32): Data handle on success, 0 on error

### Fields

#### `fieldGet(u32 field, u32 data, u32 kind) u64`

Get the value of a field into a newly allocated buffer.

Parameters:
- `field` (u32): Field handle (as returned by `dataSourceGetField` or `dataSourceAddField`)
- `data` (u32): Data handle
- `kind` (u32): Kind of access: How to read the field.

Return value:
- Value of the field:
  - If the returned value is of type String or Bytes, it will
  be allocated inside the wasm guest memory by calling the function malloc. The
  Wasm module must either provide its own implementation of malloc or be
  compiled against a library which provides it such as libc. It is the
  responsibility of the caller to free the allocation.
  - The reference Wasm guest Go library
  "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
  automatically frees the memory as appropriate so if your Wasm module uses that
  reference implementation, you don't have to call free.
  - The function returns 0 in case of errors (ambiguous with scalar types like u32).
  TODO: Find a way to report errors!

#### `fieldGetToBuffer(u32 field, u32 data, u32 kind, u64 dst) u32`

Get the value of a field of type String or Bytes into an existing buffer.

Parameters:
- `field` (u32): Field handle (as returned by `dataSourceGetField` or `dataSourceAddField`)
- `data` (u32): Data handle
- `kind` (u32): Kind of access: How to read the field.

Return value:
- Value of the field: the number of bytes copied or 0 in case of errors.

#### `fieldSet(u32 field, u32 data, u32 kind, u64 value)`

Set the value of a field.

Parameters:
- `field` (u32): Field handle (as returned by `dataSourceGetField` or `dataSourceAddField`)
- `data` (u32): Data handle
- `kind` (u32): Kind of access: How to write the field
- `value` (u64): Value to store in the field

Return value:
- None

#### `fieldAddTag(u32 field, u64 tag)`

Add a tag to the field.

Parameters:
- `field` (u32): Field handle (as returned by `dataSourceGetField` or `dataSourceAddField`)
- `tag`(string): Tag

Return value:
- None

### Parameters

Parameters passed to the WASM module are defined in the metadata file as this:

```yaml
...
params:
  wasm:
    param-key:
      key: param-key
      description: param-description
      defaultValue: param-default-value
      typeHint: param-type-hint
      title: param-title
      alias: param-alias
      isMandatory: true
    param-key2:
     ...
```

#### `getParamValue(key string) string`

Return the value of a parameter.

Parameters:
- `key` (string): Key of the parameter.

Return value:
- The value of the parameter.

### Config

#### `setConfig(key string, u64 val, u32 kind) uint32`

Sets the value of key within the gadget's configuration (gadget.yaml).

Parameters:
- `key` (string): Key to set.
- `val` (u64): Value to set.
- `kind` (u32): Kind of `val`.

Return value:
- 0 in case of success, 1 otherwise.

### eBPF Maps

#### `newMap(name string, typ uint32, keySize uint32, valueSize uint32, maxEntries uint32) uint32`

Create a new eBPF map.

Parameters:
- `name` (string): Map's name
- `typ` (u32): Map's type
- `keySize` (u32): Map's keys size
- `valueSize` (u32): Map's values size
- `maxEntries` (u32): Map's max entries

Return value:
- (u32) Handle to map on success, 0 on error.

#### `getMap(name string) uint32`

Get a handle to an existing eBPF map.
It is required to release the handle through `releaseHandle(uint32)`

Parameters:
- `name` (string): Map's name

Return value:
- (u32) Handle to map on success, 0 on error.

#### `mapLookup(m uint32, keyptr uint64, valueptr uint64) uint32`

Lookup the map for a value corresponding to given key.
When looking up a [map of maps](https://docs.kernel.org/bpf/map_of_maps.html),
this function returns a map handle which has to be released.

Parameters:
- `m` (u32): Map handle (as returned by `getMap`)
- `keyptr` (u64): A `bufPtr` to key.
- `valueptr` (u64): A `bufPtr` pointer to store the value of the map.

Return value:
- 0 in case of success, 1 otherwise.

#### `mapUpdate(m uint32, keyptr uint64, valueptr uint64, flags uint64) uint32`

Update the value corresponding to key in the given map.

Parameters:
- `m` (u32): Map handle (as returned by `getMap`)
- `keyptr` (u64): A `bufPtr` to data corresponding to key.
- `valueptr` (u64): A `bufPtr` to data corresponding to value.
- `flags` (u64): A set of flags used to modify the update behavior. Correct values are documented [here](https://github.com/cilium/ebpf/blob/061e86d8f5e9/map.go#L790-L801).

Return value:
- 0 in case of success, 1 otherwise.

#### `mapDelete(m uint32, keyptr uint64) uint32`

Delete the value corresponding to key in the given map.

Parameters:
- `m` (u32): Map handle (as returned by `getMap`)
- `keyptr` (u64): A `bufPtr` to data corresponding to key.

Return value:
- 0 in case of success, 1 otherwise.

#### `mapRelease(m uint32) uint32`

Close the map created by `newMap()`.
The map handle is released and can no longer be used.

Parameters:
- `m` (u32): Map handle (as returned by `newMap()`)

Return value:
- 0 in case of success, 1 otherwise.

### Handles

#### `releaseHandle(h uint32) uint32`

Releases the handle

Parameters:
- `h` (u32): handle

Return value:
- 0 in case of success, 1 otherwise.

### Syscalls

#### `getSyscallName(id uint32) uint64`

Get the syscall name for this syscall ID.

Parameters:
- `id` (u32): Syscall ID

Return value:
- (u64) A string containing the name of the syscall, in case the syscall is unknown, it returns "syscall_ID" with ID displayed as hexadecimal like strace.

#### `getSyscallDeclaration(name uint64, pointer uint64) uint32`

Get the syscall declaration for this syscall name.

Parameters:
- `name` (u64): Syscall name.
- `pointer` (u64): A pointer to a ` structure, which definition is shown below. It is used to store the data instead of returning them.

```golang
type syscallDeclaration struct {
	name     [32]byte
	nrParams uint8
	_        [3]byte
	params [6]syscallParam
}
```

Return value:
- (u32) 0 in case of success, 1 otherwise.

### Perf buffer

#### `func newPerfReader(mapHandle uint32, size uint32, isOverwritable uint32) uint32`

Create a new perf buffer.

Parameters:
- `mapHandle` (u32): Map handle to a PerfEventArray map.
- `size` (u32): Perf buffer size.
- `isOverwritable` (u32): Whether the buffer is overwritable or not.

Return value:
- (u32) Handle to a perf buffer on success, 0 on error.

#### `func perfReaderPause(perfMapHandle uint32) uint32`

Pause the perf buffer.

Parameters:
- `perfMapHandle` (u32): Handle to a perf buffer.

Return value:
- (u32) 0 on success, 1 on error.

#### `func perfReaderResume(perfMapHandle uint32) uint32`

Resume the perf buffer.

Parameters:
- `perfMapHandle` (u32): Handle to a perf buffer.

Return value:
- (u32) 0 on success, 1 on error.

#### `func perfReaderRead(perfMapHandle uint32, addrBufPtr uint32) uint32`

Read the perf buffer.

Parameters:
- `perfMapHandle` (u32): Handle to a perf buffer.
- `addrBufPtr` (u32): Address to a bufptr where the record will be written. The bufptr will be allocated by the function and must be freed by the caller.

Return value:
- (u32) 0 on success, 1 on error, 2 on deadline exceeded.

#### `func perfReaderClose(perfMapHandle uint32) uint32`

Close the perf buffer.

Parameters:
- `perfMapHandle` (u32): Handle to a perf buffer.

Return value:
- (u32) 0 on success, 1 on error.

### kallsyms

#### `kallsymsSymbolExists(symbol string) uint32`

Check if a symbol exists in kallsyms.

Parameters:
- `symbol` (string): Symbol's name

Return value:
- (u32) 1 if the symbol exists, 0 otherwise.
