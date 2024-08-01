---
title: 'Metadata file'
sidebar_position: 600
description: 'Introduction to the metadata file'
---

The metadata file includes extra information about the gadget, like the name,
description, etc. This file is optional. The metadata file has to be named
`gadget.yaml` and placed in the root folder of the gadget.

### Basic Contents

The basic contents of the metadatafile are defined in
https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1#GadgetMetadata.

### Generating a metadata file

It's possible to generate (and update) the metadata file for a gadget by using
the `--update-metadata` flag when building it.

:::warning

We're considering changing how the metadata file is generated, so this support
could be changed soon.

:::

### Datasources

The `datasources` section on the file allows to define different annotations for
the datasources and their fields. These annotations control different aspects of
a field, how is it formatted, how is it aggregated, etc.

#### Annotations

This is a non exhaustive list of available annotations:

- `description`: Column description
- `columns.width`: Width to reserve for this column
- `columns.maxwidth`: Maximum width this column will be scaled to when using auto-scaling
- `columns.minwidth`: MinWidth will be the minimum width this column will be scaled to when using auto-scaling
- `columns.alignment`: Alignment of this column (left or right)
- `columns.ellipsis`: EllipsisType defines how to abbreviate this column if the value needs more space than is available (start, middle, end)
- `columns.hidden`: Hide the field from the columns output mode by default. The user can always show it by using `--fields=bar,foo`.
- `columns.fixed`: Forces the Width even when using Auto-Scaling
- `template`: Use the annotation from some predefined templates. Available templates are:
  - timestamp:
    - `columns.width: 35`, `columns.maxwidth: 35`, `columns.ellipsis: end`
  - node:
    - `columns.width: 30`, `columns.ellipsis: middle`
  - pod:
    - `columns.width: 30`, `columns.ellipsis: middle`
  - container:
    - `columns.width: 30`
  - namespace:
    - `columns.width: 30`
  - containerImageName:
    - `columns.width: 30`
  - containerImageDigest:
    - `columns.width: 30`
  - containerStartedAt:
    - `columns.hidden: true`, `columns.width: 35`
  - comm:
    - `description: Process name`, `columns.maxwidth: 16`
  - pcomm:
    - `description: The process name of the parent process`, `columns.maxwidth: 16`
  - pid:
    - `columns.minwidth: 7`, `columns.alignment: right`
  - uid:
    - `columns.minwidth: 8`, `columns.alignment: right`
  - gid:
    - `columns.minwidth: 8`, `columns.alignment: right`
  - ns:
    - `columns.hidden: true`, `columns.width: 12`, `columns.alignment: right`
  - l4endpoint:
    - `columns.minwidth: 22`, `columns.width: 40`, `columns.maxwidth: 52`
  - syscall:
    - `columns.width: 18`, `columns.maxwidth: 28`
  - errorString:
    - `columns.width: 12`
- `columns.replace`: Indicates this field must be replacing by the one on the annotation when printing it.
- `json.skip`: Skip the field when marshalling to json
