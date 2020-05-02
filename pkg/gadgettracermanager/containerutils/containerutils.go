package containerutils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"
)

/*
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>

struct cgid_file_handle
{
  //struct file_handle handle;
  unsigned int handle_bytes;
  int handle_type;
  uint64_t cgid;
};

uint64_t get_cgroupid(char *path) {
  struct cgid_file_handle *h;
  int mount_id;
  int err;
  uint64_t ret;

  h = malloc(sizeof(struct cgid_file_handle));
  if (!h)
    return 0;

  h->handle_bytes = 8;
  err = name_to_handle_at(AT_FDCWD, path, (struct file_handle *)h, &mount_id, 0);
  if (err != 0)
    return 0;

  if (h->handle_bytes != 8)
    return 0;

  ret = h->cgid;
  free(h);

  return ret;
}
*/
import "C"

func GetCgroupID(path string) (uint64, error) {
	cpath := C.CString(path)
	ret := uint64(C.get_cgroupid(cpath))
	C.free(unsafe.Pointer(cpath))
	if ret == 0 {
		return 0, fmt.Errorf("GetCgroupID on %q failed", path)
	}
	return ret, nil
}

func GetCgroup2Path(pid int) (string, error) {
	cgroupPath := ""
	if cgroupFile, err := os.Open(filepath.Join("/proc", fmt.Sprintf("%d", pid), "cgroup")); err == nil {
		defer cgroupFile.Close()
		reader := bufio.NewReader(cgroupFile)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			if strings.HasPrefix(line, "0::") {
				cgroupPath = strings.TrimPrefix(line, "0::")
				cgroupPath = strings.TrimSuffix(cgroupPath, "\n")
				break
			}
		}
	} else {
		return "", fmt.Errorf("cannot parse cgroup: %v", err)
	}
	if cgroupPath == "" {
		return "", fmt.Errorf("cannot find cgroup path in /proc/PID/cgroup")
	}
	cgroupPath = filepath.Join("/sys/fs/cgroup/unified", cgroupPath)
	if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
		return "", fmt.Errorf("cannot access cgroup %q: %v", cgroupPath, err)
	}

	return cgroupPath, nil
}

func PidFromContainerId(containerID string) (int, error) {
	if strings.HasPrefix(containerID, "docker://") {
		out, err := exec.Command("chroot", "/host", "docker", "inspect", strings.TrimPrefix(containerID, "docker://")).Output()
		if err != nil {
			return -1, err
		}
		type DockerInspect struct {
			State struct {
				Pid int
			}
		}
		var dockerInspect []DockerInspect
		err = json.Unmarshal(out, &dockerInspect)
		if err != nil {
			return -1, err
		}
		if len(dockerInspect) != 1 {
			return -1, fmt.Errorf("invalid output")
		}
		return dockerInspect[0].State.Pid, nil
	} else if strings.HasPrefix(containerID, "cri-o://") {
		out, err := exec.Command("chroot", "/host", "crictl", "inspect", strings.TrimPrefix(containerID, "cri-o://")).Output()
		if err != nil {
			return -1, err
		}
		type CRIOInspect struct {
			Pid int
		}
		var crioInspect CRIOInspect
		err = json.Unmarshal(out, &crioInspect)
		if err != nil {
			return -1, err
		}
		if crioInspect.Pid == 0 {
			return -1, fmt.Errorf("invalid pid")
		}
		return crioInspect.Pid, nil
	}
	return -1, fmt.Errorf("unknown container runtime: %s", containerID)
}
