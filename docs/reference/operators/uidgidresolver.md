---
title: UidGidResolver
---

The `UidGidResolver` data operator resolves `uid` and `gid` (user and group identifiers) values to the corresponding user and group names.
It does this by monitoring the `/etc/passwd` and `/etc/group` files on the host.
This leads to the restrictions that user and groupnames inside the guest might not be correctly resolved.
It means the events are enriched with the user and group names from the host, so the ones for the container are ignored.

### Parameters

None
