---
title: Limiter
---

The Limiter operator limits the number of entries in each batch of data. This
operator is only enabled for data sources of type array. A great scenario for
this operator is when you are already sorting data within an array of data and
you want to filter out the top `max-entries` entries.

## Priority

9600

## Instance Parameters

### `--max-entries`

The maximum number of entries for each batch of data. If using multiple array
data sources, prefix the value with 'datasourcename:' and separate with ','. If
no array data source is specified, the value will be applied to all array data
sources. Use -1 to disable the limiter.

Fully qualified name: `operator.limiter.max-entries`

Default value: `-1`
