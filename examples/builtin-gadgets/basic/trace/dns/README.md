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
$ nslookup -querytype=a microsoft.com.
$ nslookup -querytype=a google.com.
```

The first terminal will print information about the DNS requests:
```bash
$ sudo ./dns
A new "A" dns request about microsoft.com. was observed
A new "A" dns request about microsoft.com. was observed
A new "A" dns response about microsoft.com. was observed
A new "A" dns response about microsoft.com. was observed
A new "A" dns request about google.com. was observed
A new "A" dns request about google.com. was observed
A new "A" dns response about google.com. was observed
A new "A" dns response about google.com. was observed
```
