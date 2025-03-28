---
title: 'Gadget gRPC API'
sidebar_position: 30
description: 'Reference documentation for the gRPC API'
---

This document describes the gRPC API provided by Inspektor Gadget for remote control of gadgets, instance management, and trace data collection.

## api.proto​

The complete API definition can be found in [pkg/gadget-service/api/api.proto](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/pkg/gadget-service/api/api.proto)

The `api.proto` defines the core gRPC services and message types for interacting with Inspektor Gadget.

### Services​

The API provides three main services:

#### GadgetManager

Service for managing custom gadgets that are packaged as container images. This service provides more flexibility in terms of gadget deployment and configuration.

```protobuf
service GadgetManager {
  rpc GetGadgetInfo(GetGadgetInfoRequest) returns (GetGadgetInfoResponse) {}
  rpc RunGadget(stream GadgetControlRequest) returns (stream GadgetEvent) {}
}
```

- `GetGadgetInfo`: Retrieves information about a specific gadget
- `RunGadget`: Runs a custom gadget with streaming control requests and events

#### GadgetInstanceManager

Service for managing long-running gadget instances. This service enables persistent gadget deployments that can be managed across sessions.

```protobuf
service GadgetInstanceManager {
  rpc CreateGadgetInstance(CreateGadgetInstanceRequest) returns (CreateGadgetInstanceResponse) {}
  rpc ListGadgetInstances(ListGadgetInstancesRequest) returns (ListGadgetInstanceResponse) {}
  rpc GetGadgetInstance(GadgetInstanceId) returns (GadgetInstance) {}
  rpc RemoveGadgetInstance(GadgetInstanceId) returns (StatusResponse) {}
}
```

### Key Message Types

The API uses various message types to handle different aspects of gadget management, from configuration to data collection. Here's a breakdown by category:

#### Information and Configuration Messages

These messages handle metadata and configuration for gadgets:

##### GetGadgetInfoRequest

Used to request information about a gadget:

```protobuf
message GetGadgetInfoRequest {
  map<string, string> paramValues = 1;
  string imageName = 2;
  uint32 version = 3;
  uint32 flags = 4;
  bool requestExtraInfo = 5;
}
```

- `paramValues`: Map of parameter key-value pairs
- `imageName`: Name of the gadget image
- `version`: Protocol version
- `flags`: Request flags
- `requestExtraInfo`: When true, includes additional information in the response (used by commands like `inspect`)

##### GadgetInfo

Contains information about a gadget:

```protobuf
message GadgetInfo {
  string name = 1;
  string imageName = 2;
  repeated DataSource dataSources = 4;
  map<string, string> annotations = 5;
  bytes metadata = 6;
  repeated Param params = 7;
  string id = 8;
  ExtraInfo extraInfo = 9;
}
```

- `name`: Name of the gadget
- `imageName`: Name of the gadget image
- `dataSources`: List of data sources provided by the gadget
- `annotations`: Additional metadata as key-value pairs
- `metadata`: Serialized metadata
- `params`: List of parameters accepted by the gadget
- `id`: Unique identifier
- `extraInfo`: Additional information when requested (see ExtraInfo)

##### ExtraInfo and GadgetInspectAddendum

Used to provide additional information about a gadget when specifically requested:

```protobuf
message ExtraInfo {
  map<string, GadgetInspectAddendum> data = 1;
}

message GadgetInspectAddendum {
  string contentType = 1;
  bytes content = 2;
}
```

- `data`: Map of additional information pieces
- `contentType`: Type of the content (e.g., "application/json", "text/plain", "text/mermaid", "text/markdown")
- `content`: The actual content bytes

This mechanism is particularly useful for commands like `inspect` that need to retrieve detailed information about a gadget.

#### Runtime Control Messages

These messages handle the execution and control of gadgets:

##### GadgetRunRequest

Used to run a gadget with specific configuration:

```protobuf
message GadgetRunRequest {
  string imageName = 1;
  map<string, string> paramValues = 2;
  repeated string args = 3;
  uint32 version = 4;
  uint32 logLevel = 12;
  int64 timeout = 13;
}
```

- `imageName`: Name of the gadget image to run
- `paramValues`: Map of parameter key-value pairs for gadget configuration
- `args`: Additional arguments for the gadget
- `version`: Protocol version
- `logLevel`: Logging verbosity level
- `timeout`: Duration to run the gadget (in nanoseconds, 0 for no timeout)

##### GadgetControlRequest

Messages for controlling gadget execution:

```protobuf
message GadgetControlRequest {
  oneof Event {
    GadgetRunRequest runRequest = 1;
    GadgetStopRequest stopRequest = 2;
    GadgetAttachRequest attachRequest = 3;
  }
}
```

- `Event`: One of run, stop, or attach requests
- `runRequest`: Request to start a gadget
- `stopRequest`: Request to stop a gadget
- `attachRequest`: Request to attach to an existing gadget

#### Event and Data Handling

These messages handle the data and events produced by running gadgets:

##### GadgetEvent

Represents events emitted by running gadgets:

```protobuf
message GadgetEvent {
  uint32 type = 1;
  uint32 seq = 2;
  bytes payload = 3;
  uint32 dataSourceID = 4;
}
```

- `type`: Event type (upper 16 bits used for log severity)
- `seq`: Sequence number
- `payload`: Event data
- `dataSourceID`: ID of the data source that generated the event

##### Data Handling Types

Messages for handling gadget data:

```protobuf
message DataElement {
  repeated bytes payload = 1;
}

message GadgetData {
  string node = 1;
  uint32 seq = 2;
  DataElement data = 3;
}

message GadgetDataArray {
  string node = 1;
  uint32 seq = 2;
  repeated DataElement dataArray = 3;
}
```

- `payload`: Raw data bytes from the gadget
- `node`: Node where the data was collected
- `seq`: Sequence number for ordering
- `data/dataArray`: Single or multiple data elements

##### DataSource and Field Types

For structured data handling:

```protobuf
message DataSource {
  uint32 id = 1;
  string name = 2;
  uint32 type = 3;
  repeated Field fields = 4;
  repeated string tags = 5;
  map<string, string> annotations = 6;
  uint32 flags = 7;
}

message Field {
  string name = 1;
  string fullName = 2;
  uint32 index = 3;
  uint32 payloadIndex = 4;
  uint32 offs = 5;
  uint32 size = 6;
  uint32 flags = 7;
  Kind kind = 8;
  repeated string tags = 9;
  map<string, string> annotations = 10;
  uint32 parent = 11;
  int32 order = 12;
}
```

#### Instance Management Types

Messages for managing long-running gadget instances:

```protobuf
message CreateGadgetInstanceRequest {
  GadgetInstance gadgetInstance = 1;
  int32 eventBufferLength = 2;
}

message CreateGadgetInstanceResponse {
  int32 result = 1;
  GadgetInstance gadgetInstance = 2;
}

message ListGadgetInstancesRequest {}

message ListGadgetInstanceResponse {
  repeated GadgetInstance gadgetInstances = 1;
}

message GadgetInstanceId {
  string id = 1;
}

message StatusResponse {
  int32 result = 1;
  string message = 2;
}
```

- `gadgetInstance`: Configuration for the gadget instance
- `eventBufferLength`: Size of the event buffer
- `result`: Operation result code (0 for success)
- `message`: Optional status message
- `gadgetInstances`: List of running gadget instances
- `id`: Unique identifier for a gadget instance (hex characters in lowercase)

### Built-in Gadget Types (Deprecated)

> **Warning**
> Built-in gadgets are being deprecated in favor of OCI gadgets. Built-in gadgets
> will be removed in v0.42.0 (July 2025). Please migrate to their OCI counterparts.
> You can find the list of OCI gadgets in the [gadgets section](../gadgets/).

#### BuiltInGadgetManager​

Service for managing built-in gadgets that come pre-packaged with Inspektor Gadget.

```protobuf
service BuiltInGadgetManager {
  rpc GetInfo(InfoRequest) returns (InfoResponse) {}
  rpc RunBuiltInGadget(stream BuiltInGadgetControlRequest) returns (stream GadgetEvent) {}
}
```

* `GetInfo`: Retrieves information about the gadget service
* `RunBuiltInGadget`: Runs a built-in gadget with streaming control

##### InfoRequest and InfoResponse

Used to get information about the gadget service:

```protobuf
message InfoRequest {
  string version = 1;
}

message InfoResponse {
  string version = 1;
  bytes catalog = 2;
  bool experimental = 3;
  string serverVersion = 4;
}
```

- `version`: Protocol version
- `catalog`: Serialized catalog of available gadgets
- `experimental`: Whether experimental features are enabled
- `serverVersion`: Version of the gadget service

##### BuiltInGadgetRunRequest

Used to run a built-in gadget:

```protobuf
message BuiltInGadgetRunRequest {
  string gadgetName = 1;
  string gadgetCategory = 2;
  map<string, string> params = 3;
  repeated string args = 4;
  repeated string nodes = 10;
  bool fanOut = 11;
  uint32 logLevel = 12;
  int64 timeout = 13;
}
```

- `gadgetName`: Name of the gadget as returned by gadgetDesc.Name()
- `gadgetCategory`: Category of the gadget as returned by gadgetDesc.Category()
- `params`: Combined map of all parameters including runtime and operator params
- `args`: Parameters not specified with flags
- `nodes`: List of nodes to run on (empty for all nodes)
- `fanOut`: When true, forwards request to each node and combines output
- `logLevel`: Logging verbosity level
- `timeout`: Duration in nanoseconds (0 for no timeout)

##### BuiltInGadgetControlRequest

Messages for controlling built-in gadget execution:

```protobuf
message BuiltInGadgetControlRequest {
  oneof Event {
    BuiltInGadgetRunRequest runRequest = 1;
    BuiltInGadgetStopRequest stopRequest = 2;
  }
}
```

- `Event`: One of run or stop requests
- `runRequest`: Request to start a built-in gadget
- `stopRequest`: Request to stop a built-in gadget

## gadgettracermanager.proto

[pkg/gadgettracermanager/api/gadgettracermanager.proto](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/pkg/gadgettracermanager/api/gadgettracermanager.proto)

TODO
