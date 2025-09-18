// Copyright 2025 The Inspektor Gadget authors
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

package localmanager

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	// The product of these to constants defines the maximum wait
	// time before failing the checkFdList condition. These should
	// be large enough to allow all resources to be freed. These
	// only affect the duration of the failing tests, hence it's not
	// a big problem to have big delays here.
	checkFdListInterval = 100 * time.Millisecond
	checkFdListAttempts = 20
)

func TestLocalManagerBasic(t *testing.T) {
	utils.RequireRoot(t)

	// Call host.Init() as it'd be done by the local runtime. Otherwise, all
	// calls to host.IsHost*() done by container-collection enrichers will fail.
	err := host.Init(host.Config{})
	require.NoError(t, err, "Failed to initialize host")

	lm := &localManager{}
	gParams := lm.GlobalParamDescs().ToParams()
	err = lm.Init(gParams)
	require.NoError(t, err, "Failed to initialize localManager")
	lm.Close()
}

func TestLocalManagerMountNsMap(t *testing.T) {
	utils.RequireRoot(t)

	// Call host.Init() as it'd be done by the local runtime. Otherwise, all
	// calls to host.IsHost*() done by container-collection enrichers will fail.
	err := host.Init(host.Config{})
	require.NoError(t, err, "Failed to initialize host")

	lm := &localManager{}
	gParams := lm.GlobalParamDescs().ToParams()
	err = lm.Init(gParams)
	require.NoError(t, err, "Failed to initialize localManager")
	defer func() {
		err = lm.Close()
		require.NoError(t, err, "Failed to close localManager")
	}()

	id := "foo"

	err = lm.tracerCollection.AddTracer(id, containercollection.ContainerSelector{})
	require.NoError(t, err, "Failed to add tracer")
	defer func() {
		err = lm.tracerCollection.RemoveTracer(id)
		require.NoError(t, err, "Failed to remove tracer")
	}()

	mountnsmap, err := lm.tracerCollection.TracerMountNsMap(id)
	require.NoError(t, err, "Failed to get mount namespace map")
	require.NotNil(t, mountnsmap, "Mount namespace map should not be nil")
}

func currentFdList(t *testing.T) (ret string) {
	files, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err, "Failed to list fds")

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

// TestLocalManagerClose tests that resources aren't leaked after calling Close()
func TestLocalManagerClose(t *testing.T) {
	utils.RequireRoot(t)

	// Call host.Init() as it'd be done by the local runtime. Otherwise, all
	// calls to host.IsHost*() done by container-collection enrichers will fail.
	err := host.Init(host.Config{})
	require.NoError(t, err, "Failed to initialize host")

	c := testutils.NewDockerContainer("test-lm-close", "sleep inf", testutils.WithoutLogs())
	c.Start(t)
	t.Cleanup(func() {
		c.Stop(t)
	})

	initialFdList := currentFdList(t)

	lm := &localManager{}
	gParams := lm.GlobalParamDescs().ToParams()
	gParams.Set(Runtimes, "docker")

	for i := range 4 {
		err := lm.Init(gParams)
		require.NoError(t, err, "Failed to initialize localManager")

		if i%2 == 0 {
			testutils.RunDockerFailedContainer(context.Background(), t)
		}

		lm.Close()
	}

	checkFdList(t, initialFdList, checkFdListAttempts, checkFdListInterval)
}
