---
title: 'Running image based gadgets in your Go program'
weight: 40
description: >
  The runner package allows to fully utilize image based gadgets in your own Go program
---

> ⚠️ This package is experimental and could change without prior notification. Once image based gadgets transition out of the experimental state, this package will also become more stable

The [`runner package`](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget/pkg/runner) allows developers to integrate image based gadgets into their own Go programs.


## Using the `Runner`

The `runner` package provides 2 ways to create a new `Runner`.
1. `NewRunner` accepts a url to an oci repository which contains a gadget image.
   Since the image will be downloaded at this step, the call could take some time.
2. `NewRunnerFromByes` accepts a byte array which contains an eBPF program

After creation of a `Runner` everything is ready to be run and `Runner.Run()` can be called.
This step starts the gadget in the background.


## Example

```golang
func filterOnFile(r *runner.Runner, cancelFunc context.CancelFunc, file string) error {
	for !r.Done() {
		rawEvent, err := r.GetEvent()
		if err != nil {
			return fmt.Errorf("get event: %w", err)
		}

		type event struct {
			Filename string `json:"fname"`
		}
		var e event
		err = json.Unmarshal([]byte(rawEvent), &e)
		if err != nil {
			return fmt.Errorf("unmarshal event: %w", err)
		}

		if e.Filename == file {
			fmt.Println(rawEvent)
      // Cancel the context and therefore the gadget
			cancelFunc()
			return nil
		}
	}
	return nil
}

func main() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create a new runner with a timeout of 3 seconds
	r, err := runner.NewRunner("ghcr.io/inspektor-gadget/gadget/trace_open:latest",
		runner.WithPullPolicy(oci.PullImageAlways),
		runner.WithValidateMetadata(true),
		runner.WithContext(ctx),
	)
	if err != nil {
		fmt.Println("NewRunner:", err)
		return
	}
	// Make sure to close the runner instance to cleanup the resources
	defer r.Close()

	// Run the image based gadget asynchronously
	err = r.Run()
	if err != nil {
		fmt.Println("Run:", err)
		return
	}

	// Check for /etc/passwd opens asynchronously
	go filterOnFile(r, cancel, "/etc/passwd")

	// Wait for the gadget to finish
	err = r.Wait()
	if err != nil {
		fmt.Println("Wait:", err)
	}
}
```

