---
title: How to write a Gadget?
weight: 100
description: >
  How to write a built-in Gadget?
---

> ⚠️ This page is about creating built-in gadget. Once we move to image-based
> gadgets, built-in gadgets will be deprecated. We recommand reading [Hello
> world gadget](hello-world-gadget.md) instead.

So you want to write a Gadget for Inspektor Gadget? Great!

A gadget consists of a __Gadget Descriptor__ that provides metadata about your gadget and a __Gadget__ implementation
(sometimes called tracer in our codebase).

## Gadget Descriptor

The first step to writing a new gadget is providing a _Gadget Descriptor_. Simply create a new struct that implements
the [`gadgets.GadgetDesc`]( https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget@main/pkg/gadgets#GadgetDesc)
interface, providing all required information, including a name, description, category and so on.

In our example, we call this struct like the interface, `GadgetDesc`. If you want your gadget to return records of
a specific known type, for example system events as they come in, you can define a type for it (we call it
EventDataType in our example) and return a pointer to an empty version of it in the `EventPrototype()` methods and
initialize a Parser inside the `Parser()` function. This typically looks like this:

```go
func (g *GadgetDesc) EventPrototype() {
	return &EventDataType{}
}

func (g *GadgetDesc) Parser() {
	return parser.NewParser[EventDataType](nil)
}
```

If you want support for a human-readable output in the form of text columns later on,
you should annotate the fields of your data struct like explained in our
[Columns library documentation](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget/pkg/columns).
The annotation works similar to the JSON tags for struct members that you probably already know.
In that case, you should instantiate a columns helper in the `Parser()` function like so:

```go
func (g *GadgetDesc) Parser() {
	return parser.NewParser[EventDataType](columns.MustCreateColumns[EventDataType]())
}
```

In addition to the implementation of the `gadgets.GadgetDesc` interface, you must also provide a
`NewInstance() (gadgets.Gadget, error)` method on the same type, to satisfy the
[`gadgets.GadgetInstantiate`](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget@main/pkg/gadgets#GadgetInstantiate)
interface. This method should return an instance of your gadget.

> In order to avoid compilation errors on systems not supporting ebpf and kernel functions, you can move the
> `NewInstance()` method and your actual gadget code to a separate file with the special build tag `!withoutebpf`
> (the negation is important).

To be able to use the gadget afterwards, we need to register the newly created GadgetDesc with the gadget-registry.
We usually do it like this inside the init function of the file that holds your GadgetDesc:

```go
func init() {
   gadgetregistry.Register(&GadgetDesc{})
}
```

The last thing to do, is to make sure that the file containing this registration is imported somehow. You can do this
for example by adding it to `pkg/all-gadgets/gadgets.go`. (TBD)

## Gadget Implementation

Your actual code, that does the work, should live on the type you returned in the `NewInstance()` method of your
`GadgetDesc` implementation. The only mandatory method is `Init(gadgetCtx gadgets.GadgetContext) error` to satisfy the
[`gadgets.Gadget`](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget@main/pkg/gadgets#Gadget) interface.
This method will be called as soon as your gadget is executed and handed over a __Gadget Context__ (`gadgetCtx`). This
`gadgetCtx` will supply you with the filled out params (if you have configured those), a logger that you can use inside
your gadget and a `context.Context`, which you can use inside your gadget and/or to check whether it has been
cancelled, and you should stop work inside your gadget.

### Gadget Lifecycle

The lifecycle of your Gadget is controlled by several interfaces you _can_ implement, depending on how your gadget
works.

If you for example want your gadget to run for a certain time and be stopped after a certain interval or user
interaction, you might want to choose to implement the
[`gadgets.StartStopGadget`](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget@main/pkg/gadgets#StartStopGadget)
interface. This will make sure a `Start() error` is called upon executing your gadget and `Stop()` is called after the
gadget should be stopped.

> Exception: If your gadget is of type `gadgets.TypeOneShot`, Stop() will be called immediately after Start().

If you only need to know that the gadget is executed, but don't care about execution time, you can implement
[`gadgets.RunGadget`](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget@main/pkg/gadgets#RunGadget) -
which is basically just `Run() error`, from where you can return whether your gadget run was successful.

### Getting data out of your gadget

To be able to actually send data back to Inspektor Gadget, you need an __event handler__. You can get hold of one by
implementing either the
[`gadgets.EventHandlerSetter`](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget@main/pkg/gadgets#EventHandlerSetter)
or [`gadgets.EventHandlerArraySetter`](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget@main/pkg/gadgets#EventHandlerArraySetter)
interface on your gadget.

That method will then be called prior to `Start()` and `Run()`, and hand over a function that you can use as sink for
your events. This function expects you to send events/data of the type you returned as Prototype in your `GadgetDesc`
implementation, so you first need to cast it to that form. This is how such a method can look like on your gadget:

```go
func (g *Gadget) SetEventHandler(handler any) {
   nh, ok := handler.(func(ev *types.Event))
   if !ok {
      panic("event handler invalid")
   }
   g.eventCallback = nh
}
```

In this case, we store the casted eventCallback in our Gadget struct, so we can use it later to send some data.

## Gadget Lifecycle Overview

This is a list of a default lifecycle of a gadget with all interfaces implemented. It also contains handling operators
for the sake of completeness, but that was not subject of this article.

```
gadgetDesc.Instantiate()

gadget.Init(gadgetCtx)

operators.Instantiate(gadgetCtx, gadget, operatorParams)

gadget.SetEventHandler() (gadgets.EventHandlerSetter interface)
gadget.SetEventHandlerArray() (gadgets.EventHandlerArraySetter interface)
gadget.SetEventEnricher() (gadgets.EventEnricherSetter interface)

operators.PreGadgetRun()

gadget.Start() (gadgets.StartStopGadget interface)

gadget.Run() (gadgets.RunGadget interface)

if gadgetDesc.Type() != gadgets.TypeOneShot:
  // wait for user interaction or timeout

gadget.Stop() (gadgets.StartStopGadget interface)

operators.PostGadgetRun()

gadget.Close() (gadgets.CloseGadget interface)
out, err := gadget.Result() (gadgets.GadgetResult interface)
```

## Conclusion

This article showed you how you can implement a simple gadget. We will go into more advanced topics
(like subscribing to containers) in later articles.

Existing Gadgets are always a good starting point to writing your own gadget, so please check them out!
