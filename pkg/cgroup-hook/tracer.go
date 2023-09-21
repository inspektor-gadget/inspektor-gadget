// Copyright 2023 The Inspektor Gadget authors
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

package cgrouphook

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
)

type SystemdSubInterface interface {
	AddCgroup(string, uint64)
	RemoveCgroup(string, uint64)
}

var (
	dirDeletionInterval = 1 * time.Second

	cgroupNotifier     *CgroupNotifier
	cgroupNotifierOnce sync.Once
)

type CgroupNotifier struct {
	cgroupNotify *fanotify.NotifyFD
	ticker       *time.Ticker

	cgroupPathToId sync.Map // map[cgroupPath]cgroupID

	subscribers []SystemdSubInterface
	subMutex    sync.Mutex

	// set to true when Runtime is closed
	closed bool
	done   chan bool
	wg     sync.WaitGroup

	useCount      int
	useCountMutex sync.Mutex
}

func GetCgroupNotifier() (*CgroupNotifier, error) {
	var err error
	cgroupNotifierOnce.Do(func() {
		cgroupNotifier = &CgroupNotifier{}
	})
	return cgroupNotifier, err
}

func (n *CgroupNotifier) Start() {
	n.useCountMutex.Lock()
	defer n.useCountMutex.Unlock()

	// No uses before us, we are the first one
	if n.useCount == 0 {
		n.done = make(chan bool)
		n.ticker = time.NewTicker(dirDeletionInterval)

		if err := n.install(); err != nil {
			log.Errorf("installing cgroup notifier: %v", err)
			n.close()
		}

		// Open all cgroup.procs files to populate the map
		cgroupPath, _ := cgroups.CgroupPathV2AddMountpoint(".")
		filepath.WalkDir(cgroupPath, func(path string, d os.DirEntry, err error) error {
			if !d.IsDir() {
				if d.Name() == "cgroup.procs" {
					file, err := os.Open(path)
					if err != nil {
						file.Close()
					}
				}
			}
			return nil
		})
	}
	n.useCount++
}

func (n *CgroupNotifier) Stop() {
	n.useCountMutex.Lock()
	defer n.useCountMutex.Unlock()

	// We are the last user, stop everything
	if n.useCount == 1 {
		n.close()
	}
	n.useCount--
}

func (n *CgroupNotifier) Subscribe(sub SystemdSubInterface, publishOldEntries bool) {
	n.subMutex.Lock()
	n.subscribers = append(n.subscribers, sub)
	n.subMutex.Unlock()

	// Publish old entries after subscribing
	// This ensures that the subscriber always has all entries that it needs
	// It may recieve some entries twice because of that
	if publishOldEntries {
		n.cgroupPathToId.Range(func(key, value interface{}) bool {
			sub.AddCgroup(key.(string), value.(uint64))
			return true
		})
	}
}

func (n *CgroupNotifier) Unsubscribe(sub SystemdSubInterface) {
	n.subMutex.Lock()
	defer n.subMutex.Unlock()
	for i, s := range n.subscribers {
		if s == sub {
			n.subscribers = append(n.subscribers[:i], n.subscribers[i+1:]...)
			return
		}
	}
}

func (n *CgroupNotifier) publishAdd(cgroupPath string, id uint64) {
	log.Debugf("Adding cgroup %q\n", cgroupPath)
	n.subMutex.Lock()
	defer n.subMutex.Unlock()
	for _, updater := range n.subscribers {
		updater.AddCgroup(cgroupPath, id)
	}
}

func (n *CgroupNotifier) publishRemove(cgroupPath string, id uint64) {
	log.Debugf("Deleting cgroup %q\n", cgroupPath)
	n.subMutex.Lock()
	defer n.subMutex.Unlock()
	for _, updater := range n.subscribers {
		updater.RemoveCgroup(cgroupPath, id)
	}
}

func (n *CgroupNotifier) install() error {
	cgroupPath, err := cgroups.CgroupPathV2AddMountpoint(".")
	if err != nil {
		return err
	}

	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	fanotifyFlags := uint(unix.FAN_CLOEXEC | unix.FAN_CLASS_CONTENT | unix.FAN_UNLIMITED_QUEUE | unix.FAN_UNLIMITED_MARKS | unix.FAN_NONBLOCK)
	cgroupNotify, err := fanotify.Initialize(fanotifyFlags, openFlags)
	if err != nil {
		return err
	}

	n.cgroupNotify = cgroupNotify
	if err := cgroupNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, unix.FAN_OPEN_PERM, unix.AT_FDCWD, cgroupPath); err != nil {
		return fmt.Errorf("fanotify FAN_OPEN_PERM marking of %s: %w", cgroupPath, err)
	}
	n.wg.Add(2)
	go n.watchCgroupNotify()
	go n.watchDirDeletion()
	return nil
}

func (n *CgroupNotifier) watchCgroupNotify() {
	defer n.wg.Done()

	for {
		stop, err := n.watchCgroupIterate()
		if n.closed {
			n.cgroupNotify.File.Close()
			return
		}
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Errorf("error watching runtime binary: %v\n", err)
			}
		}
		if stop {
			n.cgroupNotify.File.Close()
			return
		}
	}
}

func (n *CgroupNotifier) watchCgroupIterate() (bool, error) {
	// Get the next event from fanotify.
	// Even though the API allows to pass skipPIDs, we cannot use it here
	// because ResponseAllow would not be called.
	data, err := n.cgroupNotify.GetEvent()
	if err != nil {
		return true, err
	}

	// data can be nil if the event received is from a process in skipPIDs.
	// In that case, skip and get the next event.
	if data == nil {
		return false, nil
	}

	go n.handleCgroupEvent(data)
	return false, nil
}

func (n *CgroupNotifier) handleCgroupEvent(data *fanotify.EventMetadata) {
	// Don't leak the fd received by GetEvent
	defer data.Close()
	// This unblocks the execution
	defer n.cgroupNotify.ResponseAllow(data)

	if !data.MatchMask(unix.FAN_OPEN_PERM) {
		// This should not happen: FAN_OPEN_PERM is the only mask Marked
		log.Errorf("fanotify: unknown event on runc: mask=%d pid=%d", data.Mask, data.Pid)
		return
	}

	path, err := data.GetPath()
	if err != nil {
		return
	}
	cgroupPath := filepath.Dir(path)
	if !strings.HasSuffix(cgroupPath, ".service") {
		return
	}
	base := filepath.Base(path)
	if base != "cgroup.procs" && base != "cgroup.threads" {
		return
	}
	id, err := cgroups.GetCgroupID(cgroupPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Highly likely that we got a scoped path from a "guest" e.g a docker container
			// that can't be directly used on the host
			log.Debugf("getting cgroup id: %v", err)
		} else {
			log.Errorf("getting cgroup id: %v", err)
		}
		return
	}

	oldid, ok := n.cgroupPathToId.Load(cgroupPath)
	if ok && oldid == id {
		return
	}
	n.cgroupPathToId.Store(cgroupPath, id)
	if ok {
		log.Debugf("Updating pid for service %q, %d\n", cgroupPath, id)
		n.publishRemove(cgroupPath, oldid.(uint64))
	}
	n.publishAdd(cgroupPath, id)
}

func (n *CgroupNotifier) watchDirDeletion() {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case <-n.ticker.C:
			n.removeDeletedCgroupDirs()
		}
	}
}

func (n *CgroupNotifier) removeDeletedCgroupDirs() {
	n.cgroupPathToId.Range(func(key, value interface{}) bool {
		cgroupPath := key.(string)
		if _, err := os.Stat(cgroupPath); err != nil {
			n.cgroupPathToId.Delete(cgroupPath)
			n.publishRemove(cgroupPath, value.(uint64))
		}
		return true
	})
}

func (n *CgroupNotifier) close() {
	n.closed = true
	close(n.done)
	if n.cgroupNotify != nil {
		n.cgroupNotify.File.Close()
	}
	n.wg.Wait()
}
