---
title: 'Parameters'
sidebar_position: 610
description: 'Gadget Parameters'
---

A Gadget can expose parameters to the client from the eBPF program. Inspektor
Gadget provides the mechanism to expose the parameters as CLI flags to the user
and allow to set them from the configuration file.

1. Define a constant. It's important to use `const volatile` for the verifier to remove dead code.

```c
const volatile bool myparam = false;
```

2. Mark the constant as a parameter.

```c
GADGET_PARAM(myparam);
```

3. Provide additional information for the param on the metadata file:

```yaml
params:
  ebpf:
    myparam:
      key: my-param
      defaultValue: "false"
      description: Description for the param
```
