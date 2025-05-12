// Copyright 2024 The Inspektor Gadget authors
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

package uidgidresolver

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/cachedmap"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// UserGroupCache is a cache of user names, uids, group names and gids
type UserGroupCache interface {
	Start() error
	Stop()

	GetUsername(uint32) string
	GetGroupname(uint32) string
}

type userGroupCache struct {
	userCache  cachedmap.CachedMap[uint32, string]
	groupCache cachedmap.CachedMap[uint32, string]

	loopFinished  chan struct{}
	useCount      int
	useCountMutex sync.Mutex
	watcher       *fsnotify.Watcher
}

const (
	passwdFileName = "passwd"
	groupFileName  = "group"
	baseDirPath    = "/etc"
)

var (
	fullPasswdPath    = filepath.Join(host.HostRoot, baseDirPath, passwdFileName)
	fullGroupPath     = filepath.Join(host.HostRoot, baseDirPath, groupFileName)
	GetUserGroupCache = sync.OnceValue(func() *userGroupCache {
		return &userGroupCache{}
	})
)

func (cache *userGroupCache) Start() error {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// No uses before us, we are the first one
	if cache.useCount == 0 {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return fmt.Errorf("UserGroupCache: create watcher: %w", err)
		}
		defer func() {
			// Only close the watcher if we are not going to use it
			if watcher != nil {
				watcher.Close()
			}
		}()

		err = watcher.Add(filepath.Join(host.HostRoot, baseDirPath))
		if err != nil {
			return fmt.Errorf("UserGroupCache: add watch: %w", err)
		}

		cache.userCache = cachedmap.NewCachedMap[uint32, string](2 * time.Second)
		cache.groupCache = cachedmap.NewCachedMap[uint32, string](2 * time.Second)

		// Initial read
		cache.userCache.Clear()
		cache.groupCache.Clear()
		passwdFile, err := os.OpenFile(fullPasswdPath, os.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("UserGroupCache: open /etc/passwd in host file system: %w", err)
		}
		defer passwdFile.Close()
		updateEntries(passwdFile, cache.userCache)

		groupFile, err := os.OpenFile(fullGroupPath, os.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("UserGroupCache: open %q: %w", fullGroupPath, err)
		}
		defer groupFile.Close()
		updateEntries(groupFile, cache.groupCache)

		cache.watcher = watcher
		watcher = nil
		cache.loopFinished = make(chan struct{})
		go cache.watchUserGroupLoop()
	}
	cache.useCount++
	return nil
}

func (cache *userGroupCache) Close() {
	if cache.watcher != nil {
		err := cache.watcher.Close()
		if err != nil {
			log.Warnf("UserGroupCache: close watcher: %v", err)
		}
		// Wait until the loop is finished, should be fast
		<-cache.loopFinished
		cache.watcher = nil

		cache.userCache.Close()
		cache.groupCache.Close()
	}
}

func (cache *userGroupCache) Stop() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// We are the last user, stop everything
	if cache.useCount == 1 {
		cache.Close()
	}
	cache.useCount--
}

func (cache *userGroupCache) watchUserGroupLoop() {
	defer close(cache.loopFinished)
	for {
		select {
		case event, ok := <-cache.watcher.Events:
			if !ok {
				log.Warnf("UserGroupCache: watcher event not ok")
				return
			}
			cache.handleEvent(event)
		case err, ok := <-cache.watcher.Errors:
			if !ok {
				if err == nil {
					// Watcher closed
					return
				}
				log.Warnf("UserGroupCache: watcher error not ok: %v", err)
				return
			}
			log.Warnf("UserGroupCache: watcher error: %v", err)
		}
	}
}

func (cache *userGroupCache) handleEvent(event fsnotify.Event) {
	// Filter out chmod events first, to keep string comparisons to a minimum
	if event.Has(fsnotify.Chmod) {
		return
	}

	targetFilePath := ""
	var resourceCache cachedmap.CachedMap[uint32, string]
	switch event.Name {
	case fullPasswdPath:
		targetFilePath = fullPasswdPath
		resourceCache = cache.userCache
	case fullGroupPath:
		targetFilePath = fullGroupPath
		resourceCache = cache.groupCache
	default:
		return
	}

	var targetFile *os.File
	if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
		targetFile = nil
	} else if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
		var err error
		targetFile, err = os.OpenFile(targetFilePath, os.O_RDONLY, 0)
		if err != nil {
			log.Warnf("UserGroupCache: open target file: %v", err)
			return
		}
		defer targetFile.Close()
	} else {
		// Ignore all other events
		return
	}

	updateEntries(targetFile, resourceCache)
}

func updateEntries(file *os.File, resourceCache cachedmap.CachedMap[uint32, string]) {
	oldEntries := make(map[uint32]struct{})
	for _, id := range resourceCache.Keys() {
		oldEntries[id] = struct{}{}
	}

	if file != nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimLeft(scanner.Text(), " \t")
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			split := strings.Split(line, ":")
			// We are interested only in the first and third field
			if len(split) < 3 {
				continue
			}
			name := split[0]
			id_u64, err := strconv.ParseUint(split[2], 10, 32)
			if err != nil {
				log.Warnf("UserGroupCache: convert id: %v", err)
				continue
			}
			id := uint32(id_u64)
			delete(oldEntries, id)
			resourceCache.Add(id, name)
		}
	}

	for id := range oldEntries {
		resourceCache.Remove(id)
	}
}

func (cache *userGroupCache) GetUsername(uid uint32) string {
	name, _ := cache.userCache.Get(uid)
	return name
}

func (cache *userGroupCache) GetGroupname(gid uint32) string {
	name, _ := cache.groupCache.Get(gid)
	return name
}
