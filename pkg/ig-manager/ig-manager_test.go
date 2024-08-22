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

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"

	// Yes, not the better naming for these two.
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
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

	igManager, err := NewManager(nil, nil)
	if err != nil {
		t.Fatalf("Failed to start ig manager: %s", err)
	}
	igManager.Close()
}

func TestContainersMap(t *testing.T) {
	utilstest.RequireRoot(t)

	igManager, err := NewManager(nil, nil)
	if err != nil {
		t.Fatalf("Failed to start ig manager: %s", err)
	}
	defer igManager.Close()

	if m := igManager.ContainersMap(); m == nil {
		t.Fatal("container map is nil")
	}
}

func TestMountNsMap(t *testing.T) {
	utilstest.RequireRoot(t)

	igManager, err := NewManager(nil, nil)
	if err != nil {
		t.Fatalf("Failed to start ig manager: %s", err)
	}
	defer igManager.Close()

	id := "foo"

	m, err := igManager.CreateMountNsMap(id, containercollection.ContainerSelector{})
	if err != nil {
		t.Fatalf("Failed to create mount namespace map: %s", err)
	}
	if m == nil {
		t.Fatalf("mount namespace map is nil: %s", err)
	}

	err = igManager.RemoveMountNsMap(id)
	if err != nil {
		t.Fatalf("Failed to remove mount namespace map: %s", err)
	}
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

	c := testutils.NewDockerContainer("test-ig-close", "sleep inf", testutils.WithoutLogs())
	c.Start(t)
	t.Cleanup(func() {
		c.Stop(t)
	})

	initialFdList := currentFdList(t)

	for i := 0; i < 4; i++ {
		igManager, err := NewManager([]*containerutilsTypes.RuntimeConfig{{Name: "docker"}}, nil)
		if err != nil {
			t.Fatalf("Failed to start ig manager: %s", err)
		}

		if i%2 == 0 {
			testutils.RunDockerFailedContainer(context.Background(), t)
		}

		igManager.Close()
	}

	checkFdList(t, initialFdList, checkFdListAttempts, checkFdListInterval)
}
