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

Under the hood, Inspektor Gadget uses two separate functions that control these
lifecycles. One is to get information from a gadget ("GetGadgetInfo"), one is to
actually run a gadget ("RunGadget").

While the latter runs all lifecycle steps in the order documented below, the
former will only call `Instantiate` and `Close`. That means that everything you
do in `Instantiate` should use the least possible resources, but also that
everything a gadget "offers" should be known after that step. That means: all
DataSources should be known and finalized (fields added/modified, annotations
added, etc.) after this step.

Actual work should only be done on the forthcoming hooks (`PreStart`/`Start`).
If the initialization step needs to actually create some kind of state that is
necessary for later steps in the `RunGadget` case, the `Close` hook can be used
to tear everything back down.

### Instantiate

Instances (`DataOperatorInstance` and `ImageOperatorInstance`) are created by
`InstantiateDataOperator()` and `InstantiateImageOperator()` respectively. Those
functions should return a new initalized instance of the operator. They can also
return `nil` if the operator should be skipped. Data sources should be created
in this step.

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
