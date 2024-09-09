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

Strings and byte arrays are stored in the wasm module's memory. A 64 bit
integer is used to represent a pointer to them, the higher 32 bits contains the
length and the lower 32 the memory address.

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
can suscribe to data sources, create new fields, etc. This function is optional.

### `gadgetStart`

This function is called when the gadget is started. This fuction is optional.

### `gadgegtStop`

This function is called when the gadget is stopped. It's used to clean up
things. This function is optional.

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
- `data`: Data handle

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `type` (u32): Subscription type: (0: Data, 1: Array, 2: Packet)
- `priority` (u32): Priority of the subscription. The lower the value the higher the priority.
- `cb` (u64): Opaque ID that is passed back to `dataSourceCallback` to identify the subscription.

Return value:
- 0 on sucess, 1 in case of error.

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
- (u32): Packet handle on success, 0 on error

#### `dataSourceNewPacketArray(u32 ds) u32`

Allocate a packet array instance. The returned packet has to be released with
`dataSourceEmitAndRelease` or `dataSourceRelease`.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)

Return value:
- (u32): Packet handle on success, 0 on error

#### `dataSourceEmitAndRelease(u32 ds, u32 data) u32`

Emit and release a packet instance.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `data` (u32): Packet handle (as returned by `dataSourceNewPacketSingle`)

Return value:
- 0 in case of success, 1 otherwise.

#### `dataSourceRelease(u32 ds, u32 data)`

Release a packet instance without sending it.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `data` (u32): Packet handle (as returned by `dataSourceNewPacketSingle`)

Return value:
- None

#### `dataArrayNew(d uint32) uint32`

Allocate and returne a new element on the array.

Parameters:
- `d` (u32): DataArray handle

Return value:
- (u32): Data handle on success, 0 on error

#### `dataArrayAppend(d uint32, data uint32)`

Append data to the array.

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
- `index` (u32): Data index

Return value:
- (u32): Data handle on success, 0 on error

### Fields

#### `fieldGet(u32 field, u32 data, u32 kind) u64`

Get the value of a field.

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

#### `fieldSet(u32 field, u32 data, u32 kind, u64 value)`

Set the value of a field.

Parameters:
- `field` (u32): Field handle (as returned by `dataSourceGetField` or `dataSourceAddField`)
- `data` (u32): Data handle
- `kind` (u32): Kind of access: How to write the field
  `value` (u64): Value to store in the field

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
