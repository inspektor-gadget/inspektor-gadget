---
title: SocketEnricher
---

The Socket enricher operator provides information about the socket owner, i.e.
the process that created the socket. This is used to correlate sockets and
process information in gadgets that only have information about the socket, like
networking ones. The following informatin can be get from a socket object:

- Mount namespace inode ID
- Process and Thread IDs
- User and Group IDs

## Parameters

None
