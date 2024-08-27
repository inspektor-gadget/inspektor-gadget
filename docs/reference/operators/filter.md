---
title: Filter
---

The Filter operator filters events in user space. Since the filtering is done in
user space, it's preferred to use in-ebpf filtering options provided by other
operators like [LocalManager](./localmanager.md) and
[KubeManager](./kubemanager.md) or specific
[parameters](../../gadget-devel/parameters.md) provided by each gadget.

## Instance Parameters

### `filter`

This parameter allows you to filter events based on specific field values
provided by the gadget. This is particularly useful for narrowing down the
output to entries that meet certain criteria.

The filter syntax supports the following operations:

```bash
- `columnName==value`: Matches if the content of `columnName` equals exactly `value`.
- `columnName!=value`: Matches if the content of `columnName` does not equal exactly `value`.
- `columnName>=value`: Matches if the content of `columnName` is greater than or equal to `value`.
- `columnName>value`: Matches if the content of `columnName` is greater than `value`.
- `columnName<=value`: Matches if the content of `columnName` is less than or equal to `value`.
- `columnName<value`: Matches if the content of `columnName` is less than `value`.
- `columnName~value`: Matches if the content of `columnName` matches the regular expression `value`. See [RE2 Syntax](https://github.com/google/re2/wiki/Syntax) for more details.
```

Fully qualified name: `operators.filter.filter`
