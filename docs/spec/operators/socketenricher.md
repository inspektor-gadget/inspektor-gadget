---
title: SocketEnricher
---

The Socket enricher operator provides information about the socket owner, i.e.
the process that created the socket. This is used to correlate sockets and
process information in gadgets that only have information about the socket, like
networking ones. The following information can be gotten from a socket object:

- Mount namespace inode ID
- Process name
- Process and Thread IDs
- User and Group IDs

## Priority

10

## Parameters

### `socket-enricher-fields`

List of optional fields and their sizes to be enabled on the socket enricher
using the field0=size,field1=size,... format. Disabling or reducing the size of
the optional fields can reduce the memory and CPU usage of Inspektor Gadget.
Passing 0 as the size will use the default size of 512 bytes. If a field is not
present on the list, then it's disabled. The max size of a field is 4096 and the
size must be a power of two.

Fully qualified name: `operator.SocketEnricher.socket-enricher-fields`

Default: `cwd=512,exepath=512`
