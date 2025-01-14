---
title: Lifecycle
sidebar_position: 10
description: >
  Lilfecycle of an operator
---

This section describes the different operations that can be implemented by an
operator and what is their use case.

## Priority

Operators are initialized (PreStart and Start) according to their priority and
they are closed (Stop, PreStop and Close) in the reverse order.

## Lifecycle

### Init

Only for image layer operators.

This method initializes the operator and returns any dynamic parameters it
exposes. The operator should register data sources here.

### PreStart

The PreStart() method is called before the gadget is started. The operator can
subscribe to existing data sources on here.

### Start

This method indicates the operator should start emitting data.

### Stop

The operator shouldn't emit any other data after stop has been called.

### PostStop

The PostStop() method is used to perform last minute operations after the
operator has been stopped.

### Close

The Close() method is called to shutdown the operator. It must release all
resources and stop all operations started by the methods above.
