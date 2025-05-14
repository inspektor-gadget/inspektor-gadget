---
title: Group
---

The Group operator aggregates entries in an array datasource based on specified fields and aggregates the remaining fields according to field annotations.

## Grouping

The Group operator allows you to group entries in an array by one or more fields. For example, if you have an array of network connections with fields like `source`, `destination`, and `bytes`, you can group by `source` and `destination` to aggregate the `bytes` field.

```yaml
- source: 192.168.1.1
  destination: 10.0.0.1
  bytes: 100
- source: 192.168.1.1
  destination: 10.0.0.1
  bytes: 200
- source: 192.168.1.2
  destination: 10.0.0.2
  bytes: 300
```

After grouping by `source` and `destination`, the result would be:

```yaml
- source: 192.168.1.1
  destination: 10.0.0.1
  bytes: 300
- source: 192.168.1.2
  destination: 10.0.0.2
  bytes: 300
```

## Aggregation Methods

The Group operator supports different aggregation methods for fields, which can be specified using the `group.aggregation` annotation:

- `sum`: Sum numeric values (default for numeric fields)
- `min`: Use the minimum value
- `max`: Use the maximum value
- `avg`: Calculate the average value
- `first`: Use the first value encountered (default for non-numeric fields)
- `last`: Use the last value encountered
- `concat`: Concatenate string values (only for string fields)

For string concatenation, you can specify a separator using the `group.separator` annotation. The default separator is a space.

### Examples

#### Numeric Fields

For numeric fields, you can use the following aggregation methods:

- Sum aggregation (default for numeric fields):
  ```yaml
  datasources:
    name_of_the_datasource:
      fields:
        bytes:
          annotations:
            group.aggregation: sum
  ```

- Min aggregation:
  ```yaml
  datasources:
    name_of_the_datasource:
      fields:
        latency:
          annotations:
            group.aggregation: min
  ```

- Max aggregation:
  ```yaml
  datasources:
    name_of_the_datasource:
      fields:
        max_size:
          annotations:
            group.aggregation: max
  ```

- Average aggregation:
  ```yaml
  datasources:
    name_of_the_datasource:
      fields:
        avg_time:
          annotations:
            group.aggregation: avg
  ```

#### String Fields

For string fields, you can use the following aggregation methods:

- First aggregation (default for non-numeric fields):
  ```yaml
  datasources:
    name_of_the_datasource:
      fields:
        name:
          annotations:
            group.aggregation: first
  ```

- Last aggregation:
  ```yaml
  datasources:
    name_of_the_datasource:
      fields:
        status:
          annotations:
            group.aggregation: last
  ```

- Concatenation with separator:
  ```yaml
  datasources:
    name_of_the_datasource:
      fields:
        messages:
          annotations:
            group.aggregation: concat
            group.separator: ", "
  ```

Please check the [gadget developer documentation](../../gadget-devel/gadget-ebpf-api.md) to learn how to use this operator in your gadget.

## Priority

9400

## Parameters

| Parameter | Description |
|-----------|-------------|
| `--group` | Comma-separated list of field names to group by. For multiple datasources, prefix the field name with 'datasourcename:'. Example: field1,field2 or datasource1:field1,datasource2:field2 |
