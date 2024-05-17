package containers

import (
	"fmt"
	"os/exec"
	"testing"

	"github.com/docker/go-connections/nat"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

type K8sManager struct{}

type K8sContainer struct {
	name  string
	image string
	cmd   string
}

func (c *K8sContainer) DisplayName() string {
	return "TODO"
}

// TODO: this should be an option passed from outside
const ns = "myfoonamespace"

func (c *K8sContainer) Run(t *testing.T) {
	c.Start(t)
	c.Stop(t)
}

func (c *K8sContainer) Start(t *testing.T) {
	CreateTestNamespaceCommand("myfoonamespace").Run(t)
	cmd := PodCommand(t, c.name, c.image, "myfoonamespace", `["/bin/sh", "-c"]`, c.cmd)
	cmd.Start(t)
}

func (c *K8sContainer) Stop(t *testing.T) {
	// TODO: explicitely delete the pod too?

	DeleteTestNamespaceCommand(t, ns).Run(t)
}

func (c *K8sContainer) ID() string {
	return "TODO"
}

func (c *K8sContainer) Pid() int {
	// TODO: seems difficult :(
	// perhaps this should panic here!
	return 0
}

func (c *K8sContainer) Running() bool {
	return false
}

func (c *K8sContainer) PortBindings() nat.PortMap {
	return nil
}

func (km *K8sManager) NewContainer(name, cmd string, opts ...containerOption) *TestContainer {
	c := &TestContainer{}

	// TODO: other defaults
	c.image = "docker.io/library/busybox:latest"

	// TODO: where to get namespace from?
	c.Container = &K8sContainer{
		name:  name,
		image: c.image,
		cmd:   cmd,
	}

	for _, o := range opts {
		o(&c.cOptions)
	}

	return c
}

/// --- copied from existing
// TODO: better adapt:
// - avoid using command.Command?
// - unexport them
// - later on:use the golang api directly

const (
	namespaceLabelKey   string = "scope"
	namespaceLabelValue string = "ig-integration-tests"
)

// PodCommand returns a Command that starts a pod with a specified image, command and args
func PodCommand(t *testing.T, podname, image, namespace, cmd, commandArgs string) *command.Command {
	cmdLine := ""
	if cmd != "" {
		cmdLine = fmt.Sprintf("\n    command: %s", cmd)
	}

	commandArgsLine := ""
	if commandArgs != "" {
		commandArgsLine = fmt.Sprintf("\n    args:\n    - %s", commandArgs)
	}

	cmdStr := fmt.Sprintf(`kubectl apply -f - <<"EOF"
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    run: %s
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: %s
    image: %s%s%s
EOF
`, podname, namespace, podname, podname, image, cmdLine, commandArgsLine)

	return &command.Command{
		Name:           fmt.Sprintf("Run %s", podname),
		Cmd:            exec.Command("/bin/sh", "-c", cmdStr),
		ValidateOutput: match.ExpectStringToMatch(t, fmt.Sprintf("pod/%s created\n", podname)),
	}
}

// CreateTestNamespaceCommand returns a Command which creates a namespace whom
// name is given as parameter.
func CreateTestNamespaceCommand(namespace string) *command.Command {
	cmd := fmt.Sprintf(`kubectl apply -f - <<"EOF"
apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels: {"%s": "%s"}
EOF
while true; do
  kubectl -n %s get serviceaccount default
  if [ $? -eq 0 ]; then
    break
  fi
  sleep 1
done
	`, namespace, namespaceLabelKey, namespaceLabelValue, namespace)

	return &command.Command{
		Name: "Create test namespace",
		Cmd:  exec.Command("/bin/sh", "-c", cmd),
	}
}

// DeleteTestNamespaceCommand returns a Command which deletes a namespace whom
// name is given as parameter.
// Must be used with t.Cleanup().
func DeleteTestNamespaceCommand(t *testing.T, namespace string) *command.Command {
	return &command.Command{
		Name:           "DeleteTestNamespace",
		Cmd:            exec.Command("/bin/sh", "-c", fmt.Sprintf("kubectl delete ns %s", namespace)),
		ValidateOutput: match.ExpectStringToMatch(t, fmt.Sprintf("namespace \"%s\" deleted\n", namespace)),
	}
}
