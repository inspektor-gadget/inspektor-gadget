# trace dns example

This is a basic example showing how to use
[trace/dns](https://github.com/inspektor-gadget/inspektor-gadget/tree/main/pkg/gadgets/trace/dns)
package to trace DNS requests on the host.


## How to build

```bash
$ go build .
```

## How to run

Start the tracer in a terminal.

```bash
$ sudo ./dns
```

Then, perform some DNS requests:


```bash
$ nslookup microsoft.com
$ nslookup google.com
```

The first terminal will print information about the DNS requests:
```bash
$ sudo ./dns
A new "A" dns request to microsoft.com. was executed
A new "A" dns request to microsoft.com. was executed
A new "A" dns request to microsoft.com. was executed
A new "AAAA" dns request to microsoft.com. was executed
A new "AAAA" dns request to microsoft.com. was executed
A new "AAAA" dns request to microsoft.com. was executed
A new "A" dns request to signaler-pa.clients6.google.com. was executed
A new "A" dns request to signaler-pa.clients6.google.com. was executed
A new "AAAA" dns request to signaler-pa.clients6.google.com. was executed
A new "AAAA" dns request to signaler-pa.clients6.google.com. was executed
A new "AAAA" dns request to signaler-pa.clients6.google.com. was executed
A new "A" dns request to google.com. was executed
A new "A" dns request to google.com. was executed
A new "A" dns request to google.com. was executed
A new "AAAA" dns request to google.com. was executed
A new "AAAA" dns request to google.com. was executed
A new "AAAA" dns request to google.com. was executed
```
