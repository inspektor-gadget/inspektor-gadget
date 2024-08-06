---
title: UidGidResolver
sidebar_position: 100
description: >
  Resolving UID and GID to username and groupname
---

# UidGidResolver

The `UidGidResolver` resolves user ids and group ids to their corresponding names.

This is done by reading `/etc/passwd` and `/etc/group` on the host.
Therefore any `UID` inside a container might not properly match the username inside the container.
Since the path is hardcoded usernames provided through `ldap`, `nss-systemd`, systemd units with `DynamicUser=yes`, ... will not be resolved correctly.

## Usage

### Classic gadgets

1. Implement the UidResolverInterface for the `event struct` to resolve a UID.
   The `UID` which is returned by `GetUid()` will be resolved to the corresponding username and is passed into `SetUserName(...)`
    ```go
    type UidResolverInterface interface {
      GetUid() uint32
      SetUserName(string)
    }
    ```
2. Implement the GidResolverInterface for the `event struct` to a resolve GID.
   The `GID` which is returned by `GetGid()` will be resolved to the corresponding groupname and is passed into `SetGroupName(...)`
    ```go
    type GidResolverInterface interface {
      GetGid() uint32
      SetGroupName(string)
    }
    ```

### Image based gadgets

TODO
