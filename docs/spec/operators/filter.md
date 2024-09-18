---
title: Filter
---

The Filter operator filters events in user space. Since the filtering in user
space is slower, it's preferred to use in-ebpf filtering options when possible,
as provided by other operators like [LocalManager](./localmanager.md) and
[KubeManager](./kubemanager.md) or specific
[parameters](../../gadget-devel/parameters.md) provided by each gadget.

## Priority

9000

## Instance Parameters

### `filter`

This parameter allows you to filter events based on specific field values
provided by the gadget. This is particularly useful for narrowing down the
output to entries that meet certain criteria.

The filter syntax supports the following operations:

```bash
- `field==value`: Matches if the content of `field` equals exactly `value`.
- `field!=value`: Matches if the content of `field` does not equal exactly `value`.
- `field>=value`: Matches if the content of `field` is greater than or equal to `value`.
- `field>value`: Matches if the content of `field` is greater than `value`.
- `field<=value`: Matches if the content of `field` is less than or equal to `value`.
- `field<value`: Matches if the content of `field` is less than `value`.
- `field~value`: Matches if the content of `field` matches the regular expression `value`. See [RE2 Syntax](https://github.com/google/re2/wiki/Syntax) for more details.
```

Fully qualified name: `operator.filter.filter`
