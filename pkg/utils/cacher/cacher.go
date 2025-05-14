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

package cacher

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	lastCleanupFile = "last_cleanup"     // Dummy file to track last cleanup time
	cleanUpInterval = 24 * time.Hour     // How often to clean up the cache
	cleanUpDelay    = 7 * 24 * time.Hour // How long to keep files before deleting them
)

type Cache struct {
	cachePath   string
	lastCleanup time.Time
}

func NewCache(cachePath string) (*Cache, error) {
	if err := os.MkdirAll(cachePath, os.ModePerm); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

	cache := &Cache{
		cachePath: cachePath,
	}

	if err := cache.loadLastCleanup(); err != nil {
		return nil, fmt.Errorf("loading last cleanup timestamp: %w", err)
	}

	return cache, nil
}

type CacheEntry struct {
	srcDigest  string
	srcPath    string
	cachedPath string
	hit        bool
}

func (c *Cache) NewEntry(src string, seed hash.Hash) (*CacheEntry, error) {
	hasher := seed
	if hasher == nil {
		hasher = sha256.New()
	}

	if err := calculateFileHash(src, hasher); err != nil {
		return nil, fmt.Errorf("calculating digest: %w", err)
	}

	digest := hex.EncodeToString(hasher.Sum(nil))

	cachedPath := filepath.Join(c.cachePath, digest)
	hit := fileExists(cachedPath)

	return &CacheEntry{
		srcPath:    src,
		srcDigest:  digest,
		cachedPath: cachedPath,
		hit:        hit,
	}, nil
}

func (c *Cache) loadLastCleanup() error {
	filePath := filepath.Join(c.cachePath, lastCleanupFile)
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		// create the file
		if _, err := os.Create(filePath); err != nil {
			return fmt.Errorf("creating last cleanup file: %w", err)
		}

		info, _ = os.Stat(filePath)
	} else if err != nil {
		return fmt.Errorf("checking last cleanup file: %w", err)
	}

	c.lastCleanup = info.ModTime()
	return nil
}

func (c *Cache) saveLastCleanup() error {
	filePath := filepath.Join(c.cachePath, lastCleanupFile)
	return os.Chtimes(filePath, time.Now(), time.Now())
}

func (c *Cache) Close() error {
	if time.Since(c.lastCleanup) < cleanUpInterval {
		return nil
	}

	err := filepath.Walk(c.cachePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// TODO: could it delete the last cleanup file?
			if time.Since(info.ModTime()) > cleanUpDelay {
				if err := os.Remove(path); err != nil {
					return fmt.Errorf("removing old cache entry: %w", err)
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	c.lastCleanup = time.Now()
	if err := c.saveLastCleanup(); err != nil {
		return fmt.Errorf("saving last cleanup timestamp: %w", err)
	}

	return nil
}

func (c *CacheEntry) Get() (bool, string) {
	if c.hit {
		// Update last used time
		os.Chtimes(c.cachedPath, time.Now(), time.Now())

		return true, c.cachedPath
	}
	return false, ""
}

func (c *CacheEntry) Put(path string) error {
	// if the cache was a hit we don't need to create it
	if c.hit {
		return nil
	}
	err := copyFile(path, c.cachedPath)
	if err != nil {
		return fmt.Errorf("copying file: %w", err)
	}
	return nil
}

func calculateFileHash(filePath string, hasher hash.Hash) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("calculating hash: %w", err)
	}

	return nil
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("creating destination file: %w", err)
	}
	defer destFile.Close()

	if _, err = io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("copying file content: %w", err)
	}

	if err = destFile.Sync(); err != nil {
		return fmt.Errorf("syncing destination file: %w", err)
	}

	return nil
}
