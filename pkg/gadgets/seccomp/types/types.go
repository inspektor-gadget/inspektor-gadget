package types

import (
	"encoding/json"
	"fmt"

	"github.com/opencontainers/runtime-spec/specs-go"
)

type SeccompAdvisorQueryResponse struct {
	Node       string      `json:"node"`
	Containers []Container `json:"containers"`
}

type Container struct {
	Mntns uint64 `json:"-"`

	Namespace     string              `json:"namespace"`
	Podname       string              `json:"podname"`
	ContainerName string              `json:"container"`
	SeccompPolicy *specs.LinuxSeccomp `json:"seccomp_policy"`
}

func (c *Container) Dump() (out string) {
	out += fmt.Sprintf("Container %s/%s/%s (mntns=%v):\n", c.Namespace, c.Podname, c.ContainerName, c.Mntns)
	b, err := json.MarshalIndent(c.SeccompPolicy, "", "  ")
	if err != nil {
		out += fmt.Sprintf("    err=%s\n", err)
		return
	}
	out += fmt.Sprintf("%s\n", string(b))
	return
}
