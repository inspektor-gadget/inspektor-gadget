// Copyright 2021-2023 The Inspektor Gadget authors
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

package igmanager

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	// Yes, not the better naming for these two.
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
)

const (
	// The product of these to contansts defines the maximum wait
	// time before failing the checkFdList condition. These should
	// be large enough to allow all resources to be freeded. These
	// only affect the duration of the failing tests, hence it's not
	// a big problem to have big delays here.
	checkFdListInterval = 100 * time.Millisecond
	checkFdListAttempts = 20
)

func TestBasic(t *testing.T) {
	utilstest.RequireRoot(t)

	igManager, err := NewManager(context.TODO(), &Config{
		TestOnly:               true,
		PinPath:                "",
		ContainerRuntimeConfig: nil,
	}, nil)
	require.NoError(t, err, "Failed to create IG Manager")
	require.NotNil(t, igManager, "IG Manager should not be nil")

	igManager.Close()
}

func currentFdList(t *testing.T) (ret string) {
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("Failed to list fds: %s", err)
	}
	for _, file := range files {
		fd, err := strconv.Atoi(file.Name())
		if err != nil {
			continue
		}
		dest, err := os.Readlink("/proc/self/fd/" + file.Name())
		if err != nil {
			continue
		}
		ret += fmt.Sprintf("%d: %s\n", fd, dest)
	}
	return
}

func checkFdList(t *testing.T, initialFdList string, attempts int, sleep time.Duration) {
	for i := 0; ; i++ {
		finalFdList := currentFdList(t)
		if initialFdList == finalFdList {
			return
		}

		if i >= (attempts - 1) {
			t.Fatalf("After %d attempts, fd leaked:\n%s\n%s", attempts, initialFdList, finalFdList)
		}

		time.Sleep(sleep)
	}
}

// TestClose tests that resources aren't leaked after calling Close()
func TestClose(t *testing.T) {
	utilstest.RequireRoot(t)
	utilstest.HostInit(t)

	c := testutils.NewDockerContainer("test-ig-close", "sleep inf", testutils.WithoutLogs())
	c.Start(t)
	t.Cleanup(func() {
		c.Stop(t)
	})

	initialFdList := currentFdList(t)

	// Add containerFanotifyEbpf to capture failed containers at runtime
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithContainerFanotifyEbpf(),
	}

	for i := range 4 {
		igManager, err := NewManager(context.TODO(), &Config{
			TestOnly:               true,
			PinPath:                "",
			ContainerRuntimeConfig: []*containerutilsTypes.RuntimeConfig{{Name: "docker"}},
		}, opts)
		require.NoError(t, err, "Failed to create IG Manager")
		require.NotNil(t, igManager, "IG Manager should not be nil")

		if i%2 == 0 {
			testutils.RunDockerFailedContainer(context.Background(), t)
		}

		igManager.Close()
	}

	checkFdList(t, initialFdList, checkFdListAttempts, checkFdListInterval)
}

func TestTracer(t *testing.T) {
	utilstest.RequireRoot(t)
	utilstest.HostInit(t)

	igManager, err := NewManager(context.TODO(), &Config{
		// TestOnly is set to false because we want to test the
		// actual creation of mountnsmap(s).
		TestOnly:               false,
		PinPath:                "",
		ContainerRuntimeConfig: nil,
	}, nil)
	require.NoError(t, err, "Failed to create IG Manager")
	require.NotNil(t, igManager, "IG Manager should not be nil")
	defer igManager.Close()

	// Add 3 Tracers
	var mountnsmap *ebpf.Map
	for i := 0; i < 3; i++ {
		mountnsmap, err = igManager.CreateMountNsMap(
			fmt.Sprintf("my_tracer_id%d", i),
			containercollection.ContainerSelector{
				K8s: containercollection.K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: fmt.Sprintf("this-namespace%d", i),
					},
				},
			},
		)
		require.NoError(t, err, "Failed to create mount namespace map")
		require.NotNil(t, mountnsmap, "Mount namespace map should not be nil")
	}

	require.Equal(t, 3, igManager.TracerCount(), "Tracer count should be 3")

	// Check error on duplicate tracer
	mountnsmap, err = igManager.CreateMountNsMap(
		fmt.Sprintf("my_tracer_id%d", 0),
		containercollection.ContainerSelector{
			K8s: containercollection.K8sSelector{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace: fmt.Sprintf("this-namespace%d", 0),
				},
			},
		},
	)
	require.Error(t, err, "Expected error when creating duplicate tracer")
	require.Nil(t, mountnsmap, "Mount namespace map should be nil for duplicate tracer")

	// Remove non-existent Tracer
	err = igManager.RemoveMountNsMap(fmt.Sprintf("my_tracer_id%d", 99))
	require.Error(t, err, "Expected error when removing non-existent tracer")

	// Remove 1 Tracer
	err = igManager.RemoveMountNsMap(fmt.Sprintf("my_tracer_id%d", 1))
	require.NoError(t, err, "Failed to remove tracer")

	// Check content
	require.Equal(t, 2, igManager.TracerCount(), "Tracer count should be 2")
	assert.True(t, igManager.TracerExists("my_tracer_id0"), "Tracer my_tracer_id0 should exist")
	assert.False(t, igManager.TracerExists("my_tracer_id1"), "Tracer my_tracer_id1 should not exist")
	assert.True(t, igManager.TracerExists("my_tracer_id2"), "Tracer my_tracer_id2 should exist")

	// Remove remaining Tracers
	err = igManager.RemoveMountNsMap(fmt.Sprintf("my_tracer_id%d", 0))
	require.NoError(t, err, "Failed to remove tracer")
	err = igManager.RemoveMountNsMap(fmt.Sprintf("my_tracer_id%d", 2))
	require.NoError(t, err, "Failed to remove tracer")
	require.Equal(t, 0, igManager.TracerCount(), "Tracer count should be 0 after removing all tracers")
}
