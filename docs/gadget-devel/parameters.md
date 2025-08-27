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

## Customizable parameters

Much of Inspektor Gadget's functionality is controlled by parameters and
annotations. To give gadget authors more freedom, one can define new parameters
that affect a group of other parameters, datasource and field annotations, operator's
configuration or any other field in the metadata file. This works by patching the
gadget metadata itself, depending on those custom parameters' values.

In the `gadget.yaml`, create a new section called `custom` to `params` like this:

```yaml
params:
  custom:
    myCustomParam:
      description: A parameter that will apply a patch based on one of the possible values.
      defaultValue: "option1"
      values:
        option1:
          patch:
            datasources:
              myDataSource:
                annotations:
                  columns.output: none
    mySecondParam:
      description: Another parameter. This will apply a patch globally, regardless of the actual value.
      defaultValue: "default"
      patch:
        datasources:
          myDataSource:
            annotations:
              my.annotation: >-
                A template driven value, now {{call .getParamValue "custom.mySecondParam"}}.
              my.second.annotation: >-
                We can also access other configuration values, like the gadget name: {{call .getConfig "name"}}
```

All keys below `custom` will become new parameters that can be set by the user
of the gadget. Depending on the parameters' value, a `patch` node will be applied
to the gadget metadata itself. (See `myCustomParam` example above.)

If no specific values are configured, a global `patch` section will be applied. (See
`mySecondParam` example above.)

Strings used can use templates (explained [here](https://pkg.go.dev/text/template)).
Functions available to the templating engine are:

### getParamValue(paramName)

Can be used to get the value of any set parameter; paramName needs to be fully qualified, e.g.
`custom.mySecondParam` or `operator.oci.ebpf.target_family`.

### getConfig(key)

Can be used to get the value of any metadata key like `name`,
`params.custom.myCustomParam.description`, etc.
