---
title: Environment Variables
---

The Environment Variable operator lets you add fields containing environment variables to datasources. This helps with
adding host related information to events.

In order to do so, you first need to add the names of allowed environment variables to the `--env-vars` parameter and
then add an annotation to the datasource you want to contain the new field like so:

```yaml
datasources:
  mydatasource:
    annotations:
      env.fields.myfieldname: MYENVVAR
```

This example will add a field named `myfieldname` to the datasource `mydatasource` with the static value of the
environment variable called `MYENVVAR`.

It is important to note that environment variables will always be read from the host that runs the gadget and _not_
on the client side.

## Priority

1

## Parameters

### Global Parameters

#### `env-vars`

Comma-separated list of environment variables that are allowed to be included in datasources.

Default: empty

## Annotations

### Data Source Annotations

#### `env.fields.FIELDNAME`

You can use multiple annotations like this (having distinctive `FIELDNAME` values) to add new fields to a
datasource. The value of the annotation should be the name of the environment variable that you want the field to
contain.
