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
- [from_file](./simple/from_file/): Run a gadget from a tarball.
- [from_memory](./simple/from_memory/): Embed and run a gadget from the application binary.

### Operators

Examples showing how to use some of the operators.

- [local_manager](./operators/local_manager/): Use the local manager operator
to filter and enrich events with container data.
- [cli](./operators/cli/): Use the CLI operator to print data to the terminal.

### Datasource

Examples showing how to use `datasource`

- [fields](./datasource/fields/): Show how to access specific fields from the datasource.
- [mutate](./datasource/mutate/): Mutate and add fields to a datasource.

### Executing Gadgets on remote Inspektor Gadget instances

Examples showing how to execute gadgets in remote instances of Inspektor Gadget
(either `ig` or `ig-k8s`) by using the gRPC runtime.

- [custom_operator](./grpc/custom_operator/): Run a remote gadget and print its
  output to the terminal in json format by using a custom operator.
