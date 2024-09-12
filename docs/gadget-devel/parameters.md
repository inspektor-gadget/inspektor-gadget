---
title: 'Parameters'
sidebar_position: 610
description: 'Gadget Parameters'
---

## Parameters from eBPF programs

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

## Parameters from metadata (gadget.yaml)

Much of Inspektor Gadget's functionality is controlled by parameters and
annotations. To give gadget authors more freedom, you can define new parameters
that affect a group of other parameters or annotations.

In the `gadget.yaml`, create a new section called `custom` to `params` like this:

```yaml
params:
  custom:
    myCustomParam:
      description: Description for the param
      defaultValue: "option1"
      values:
        option1:
          applyConfig:
            datasources:
              myDataSource:
                annotations:
                  columns.output: none
    mySecondParam:
      values:
        '*':
          applyConfig:
            datasources:
              myDataSource:
                annotations:
                  my.annotation: >-
                    A template driven value, now {{index .paramValues "custom.mySecondParam"}}.
                  my.second.annotation: >-
                    We can also access other configuration values, like the gadget name: {{call .getConfig "name"}}
```

Details: tbd