### Gadgets Examples

This folder contains different examples of how gadgets can be run from a Golang
application.

> [!WARNING]
> These examples are work in progress. Be sure to check the release notes to
> understand relevant changes on the API.

TODO: link to API and concepts documentation before

### Simple Gadgets

Examples showing how to use some gadgets in their simplest configuration.

- [trace_open](./simple/trace_open/): Run the `trace_open` gadget and print the
  events to the terminal in json format.
- [trace_dns](./simple/trace_dns/): Run the `trace_dns` gadget with some of the
  operators it requires.

### Operators

Examples showing how to use some of the operators.

- [local_manager](./operators/local_manager/): Use the local manager operator
to filter and enrich events with container data.

### Datasource

Examples showing how to use `datasource`

- [fields](./datasource/fields/): Show how to access specific fields from the datasource.
