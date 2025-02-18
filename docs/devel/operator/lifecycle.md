---
title: Lifecycle
sidebar_position: 10
description: >
  Lilfecycle of an operator
---

This section describes the different hooks that can be implemented by an
operator and what their use case is.

## Priority

Operators are initialized (PreStart and Start) according to their priority and
they are closed (Stop, PreStop and Close) in the reverse order.

## Lifecycle

### Instantiate

Instances (`DataOperatorInstance` and `ImageOperatorInstance`) are created by
`InstantiateDataOperator()` and `InstantiateImageOperator()` respectively. Those
functions should return a new initalized instance of the operator. They can also
return `nil` is the operator should be skipped. Data sources should be created
on this step.

### PreStart (optional)

The PreStart() method is called before the gadget is started. The operator can
subscribe to existing data sources here.

### Start

This method indicates the operator should start emitting data.

### Stop

The operator shouldn't emit any other data after stop has been called.

### PostStop (optional)

The PostStop() method is used to perform last minute operations after the
operator has been stopped.

### Close

The Close() method is called to shutdown the operator. It must release all
resources and stop all operations started by the methods above.

### ExtraParams (optional)

The ExtraParams() method is used to expose parameters to control the operator.
