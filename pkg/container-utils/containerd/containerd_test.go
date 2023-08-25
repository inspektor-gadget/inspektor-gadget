package containerd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
)

func TestNamespace(t *testing.T) {
	test.RequireRoot(t)

	// validate the container in k8s.io (default for ig) namespace
	c1 := testutils.NewContainerdContainer("test-k8s-io", "sleep inf")
	c1.Start(t)
	k8sClient, err := NewContainerdClient("", nil)
	t.Cleanup(func() {
		k8sClient.Close()
		c1.Stop(t)
	})
	require.Nil(t, err)
	require.NotNil(t, k8sClient)

	container, err := k8sClient.GetContainer("test-k8s-io")
	require.Nil(t, err)
	require.NotNil(t, container)
	require.Equal(t, "test-k8s-io", container.Runtime.ContainerID)
	require.Equal(t, "test-k8s-io", container.Runtime.ContainerName)

	// validate the container in default (default for containerd) namespace
	c2 := testutils.NewContainerdContainer("test-default", "sleep inf", testutils.WithNamespace("default"))
	c2.Start(t)
	defaultClient, err := NewContainerdClient("", &containerutilsTypes.ExtraConfig{Namespace: "default"})
	t.Cleanup(func() {
		defaultClient.Close()
		c2.Stop(t)
	})
	require.Nil(t, err)
	require.NotNil(t, defaultClient)

	container, err = defaultClient.GetContainer("test-default")
	require.Nil(t, err)
	require.NotNil(t, container)
	require.Equal(t, "test-default", container.Runtime.ContainerID)
	require.Equal(t, "test-default", container.Runtime.ContainerName)

	// validate we can't see the container in empty-ns namespace
	emptyClient, err := NewContainerdClient("", &containerutilsTypes.ExtraConfig{Namespace: "empty-ns"})
	t.Cleanup(func() {
		emptyClient.Close()
	})
	require.Nil(t, err)
	require.NotNil(t, emptyClient)

	containers, err := k8sClient.GetContainers()
	require.Nil(t, err)
	require.NotNil(t, containers)
	require.GreaterOrEqual(t, len(containers), 1)

	containers, err = defaultClient.GetContainers()
	require.Nil(t, err)
	require.NotNil(t, containers)
	require.GreaterOrEqual(t, len(containers), 1)

	containers, err = emptyClient.GetContainers()
	require.Nil(t, err)
	require.NotNil(t, containers)
	require.Len(t, containers, 0)
}
