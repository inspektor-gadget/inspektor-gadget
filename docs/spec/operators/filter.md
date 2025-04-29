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

### filter

This parameter allows you to filter events based on specific field values
provided by the gadget. This is particularly useful for narrowing down the
output to entries that meet certain criteria.

The filter syntax supports the following operations:

- `field==value`: Matches if the content of `field` equals exactly `value`.
- `field!=value`: Matches if the content of `field` does not equal exactly `value`.
- `field>=value`: Matches if the content of `field` is greater than or equal to `value`.
- `field>value`: Matches if the content of `field` is greater than `value`.
- `field<=value`: Matches if the content of `field` is less than or equal to `value`.
- `field<value`: Matches if the content of `field` is less than `value`.
- `field~value`: Matches if the content of `field` matches the regular expression `value`. See [RE2 Syntax](https://github.com/google/re2/wiki/Syntax) for more details.

:::info

It's recommended to wrap the **entire** filter expression with single quotes when using filters containing special characters to avoid unexpected behavior.

[CLI](../../reference/run.mdx) example:

```bash
--filter 'proc.comm~^ba.*$'
```

[Gadget instance manifest](../../reference/manifests.mdx) example:

```yaml
operator.filter.filter: 'proc.comm~^ba.*$'
```

:::

Fully qualified name: `operator.filter.filter`

### multiple filters

You can specify multiple filters by separating them with a comma. The filter `field1==value1,field2==value2` will match only events where `field1` equals `value1` and `field2` equals `value2`.
Also, you can use backslash (`\`) to escape comma in the value.
