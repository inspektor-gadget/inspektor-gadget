---
title: Sort
---

The Sort operator sorts the output. This operator is only enabled for data
sources of type array. This operation is performed on the server side.

## Priority

9500

## Instance Parameters

### `sort`

Sort by fields. Join multiple fields with ','. Prefix a field with '-' to sort
in descending order. If using multiple data sources, prefix fields with
'datasourcename:' and separate with ';'

Fully qualified name: `operator.sort.sort`
