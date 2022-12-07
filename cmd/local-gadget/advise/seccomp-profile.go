// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package advise

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	commonadvise "github.com/inspektor-gadget/inspektor-gadget/cmd/common/advise"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	seccompAdviseTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
)

const localGadgetSubKey = "local-gadget-key"

func newSeccompProfileCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		if commonFlags.Containername == "" {
			return commonutils.WrapInErrMissingArgs("--containername / -c")
		}

		localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
		if err != nil {
			return commonutils.WrapInErrManagerInit(err)
		}
		defer localGadgetManager.Close()

		tracer, err := seccompAdviseTracer.NewTracer()
		if err != nil {
			return fmt.Errorf("creating tracer: %w", err)
		}
		defer tracer.Close()

		var mntns uint64
		containerNotifier := make(chan error)

		// Subscribe to container creation and termination events. Termination
		// is used to generate a profiles when a container terminates. Creation
		// is used to store the container mount namespace in case it wasn't
		// already running when gadget was launched.
		containers := localGadgetManager.ContainerCollection.Subscribe(
			localGadgetSubKey,
			containercollection.ContainerSelector{
				Name: commonFlags.Containername,
			},
			func(event containercollection.PubSubEvent) {
				switch event.Type {
				case containercollection.EventTypeAddContainer:
					if mntns != 0 {
						containerNotifier <- fmt.Errorf("multiple containers with name %q",
							commonFlags.Containername)
						break
					}

					mntns = event.Container.Mntns
				case containercollection.EventTypeRemoveContainer:
					containerNotifier <- nil
				}
			},
		)
		defer localGadgetManager.ContainerCollection.Unsubscribe(localGadgetSubKey)

		n := len(containers)
		if n > 1 {
			return fmt.Errorf("multiple containers with name %q",
				commonFlags.Containername)
		}

		// If the container already exists, we store the mntns to generate the
		// profile later. Otherwise, the mntns will be retrieved on the
		// EventTypeAddContainer event.
		if n == 1 {
			mntns = containers[0].Mntns
		}

		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

		// The profile can be generated upon container termination or when user
		// requests it through a signal.
		select {
		case <-stop:
		case err := <-containerNotifier:
			if err != nil {
				return err
			}
		}

		return printProfile(tracer, mntns)
	}

	cmd := commonadvise.NewSeccompProfileCmd(runCmd)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}

func printProfile(tracer *seccompAdviseTracer.Tracer, mntns uint64) error {
	if mntns == 0 {
		return fmt.Errorf("impossible to retrieve mount namespace")
	}

	// Get the list of syscalls from the BPF hash map and generate the seccomp
	// profile.
	syscallNames, err := tracer.Peek(mntns)
	if err != nil {
		return fmt.Errorf("peeking syscalls for mntns %d: %w", mntns, err)
	}
	profile := seccompAdviseTracer.SyscallNamesToLinuxSeccomp(syscallNames)
	output, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling seccomp profile: %w", err)
	}
	fmt.Println(string(output))

	return nil
}
