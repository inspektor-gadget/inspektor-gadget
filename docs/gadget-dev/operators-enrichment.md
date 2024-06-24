---
title: Built-in operators for data enrichment
description: >
  This section contains information on built-in operators that can
  be used to enrich or manipulate existing data.
weight: 200
---

Operators that provide enrichments are usually triggered by one of two conditions:

* Your data sources contain fields with a specific tag (usually auto-tagges when used from eBPF programs)
* You added specific annotations to the gadget.yaml file

## formatters

The formatters operator can convert data from one format into another.
It usually looks for tags on fields and automatically creates new fields
to which it writes the converted value.

### Tags for field conversion

### `type:gadget_l3endpoint_t`

`gadget_l3endpoint_t` is a type from the IG C macros that can be used to
hold layer 3 network information (IP version + IP address). The formatter
operator will convert it into a string representation like `127.0.0.1` or
`::1` and write it to a sub-field named `string`.

### `type:gadget_l4endpoint_t`

`gadget_l4endpoint_t` is another type from the IG C macros that can be used
to convert layer 4 network information to a string representation.
The resulting string will be written to a sub-field named `string` and
in the form of `127.0.0.1:8080`.

### `type:gadget_timestamp`

`gadget_timestamp` is also a type from the IG C macros that can be used
to store a timestamp (usually gotten with `bpf_ktime_get_boot_ns()`). If
found on a struct, IG will autocorrect the timestamp and also add a new
field containing a human-readable version. The new field will receive
the `columns.template: timestamp` annotation.

#### Annotations

| Annotation                  | Description  | Default                                                                                                                    |
|-----------------------------|--------------|----------------------------------------------------------------------------------------------------------------------------|
| formatters.timestamp.target | Target Field | none, but if the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix |
| formatters.timestamp.format | Formatting   | 2006-01-02T15:04:05.000000000Z07:00 (see https://pkg.go.dev/time#pkg-constants for more information)                       |

### `type:gadget_signal`

`gadget_signal` is another type from the IG C macros. Numeric signal values will be converted
to the Linux signal names like `SIGKILL`, `SIGINT`, etc., and written to the target field.

#### Annotations

| Annotation               | Description  | Default                                                                                                                    |
|--------------------------|--------------|----------------------------------------------------------------------------------------------------------------------------|
| formatters.signal.target | Target Field | none, but if the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix |

### `type:gadget_syscall`

`gadget_syscall` is another type from the IG C macros. Numeric signal values will be converted
to the Linux syscall names and written to the target field.

#### Annotations

| Annotation                | Description  | Default                                                                                                                    |
|---------------------------|--------------|----------------------------------------------------------------------------------------------------------------------------|
| formatters.syscall.target | Target Field | none, but if the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix |

## kubemanager

The kubemanager operator enriches your data with information related to the Kubernetes runtime.

### `type:gadget_mntns_id`

`gadget_mntns_id` is a type from the IG C macros that can be used to store the mount namespace id (see
https://man7.org/linux/man-pages/man7/mount_namespaces.7.html). Using that ID, IG is able to look up container
information and enrich your data with `podname`, `namespace`, `containername` and so on.

> Currently, you can only use one field of this type on a struct.

#### Added fields

| Field             | Description                                      |
|-------------------|--------------------------------------------------|
| k8s.node          | Name of the k8s node                             |
| k8s.namespace     | Name of the k8s namespace                        |
| k8s.podName       | Name of the k8s pod                              |
| k8s.containerName | Name of the k8s container name                   |
| k8s.hostnetwork   | true, if the container is using the host network |

## localmanager

The localmanager operator enriches your data with information related to the used container runtime.

#### Added fields

| Field                        | Description                                      |
|------------------------------|--------------------------------------------------|
| runtime.containerName        | Name of the container on the container runtime   |
| runtime.runtimeName          | Name of the used container runtime               |
| runtime.containerId          | ID of the container                              |
| runtime.containerImageName   | name of the container image, e.g. `nginx:latest` |
| runtime.containerImageDigest | digest (hash value) of the container image       |


