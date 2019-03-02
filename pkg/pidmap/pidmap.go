package pidmap

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type PidMap struct {
	quit chan struct{}

	pidmap map[uint32]string
}

const (
	pidmapPath = "/sys/fs/bpf/pidmap"
)

func (pm *PidMap) createMap() {
	_ = os.Remove(pidmapPath)

	prog := "bpftool"
	args := []string{
		"map",
		"create",
		pidmapPath,
		"type",
		"hash",
		"key",
		"4",
		"value",
		"64",
		"entries",
		"65536",
		"name",
		"pidmap",
		"flags",
		"1", // BPF_F_NO_PREALLOC
	}

	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		panic(fmt.Errorf("failed to create map: %s\n%s", err, output))
	}
}

func (pm *PidMap) Start() {
	pm.quit = make(chan struct{})
	pm.pidmap = make(map[uint32]string)
	pm.createMap()

	go func() {
		for {
			select {
			case <-pm.quit:
			case <-time.After(time.Second):
				pm.Update()
			}
		}
	}()
}
func (pm *PidMap) Stop() {
	close(pm.quit)
}

func (pm *PidMap) Update() {
	f, err := os.Open("/proc")
	if err != nil {
		fmt.Printf("cannot open /proc\n")
	}

	procs, err := f.Readdirnames(0)
	if err != nil {
		fmt.Printf("cannot list /proc\n")
	}

	nextPidmap := make(map[uint32]string)
	pidmapToAdd := make(map[uint32]string)
	pidmapToRemove := make(map[uint32]string)

	for _, proc := range procs {
		pid, err := strconv.Atoi(proc)
		if err != nil {
			// ignore /proc files that are not processes
			continue
		}

		content, err := ioutil.ReadFile(filepath.Join("/proc", proc, "cgroup"))
		if err != nil {
			// ignore the error: the process just terminated
			continue
		}
		lines := strings.Split(string(content), "\n")
		id := ""
		for _, line := range lines {
			if !strings.HasPrefix(line, "1:") {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) != 3 {
				continue
			}
			path := fields[2]
			parts := strings.Split(path, "/")
			for i := range parts {
				if (parts[i] == "docker" || parts[i] == "docker.service") && len(parts) > i+1 {
					id = parts[i+1]
					break
				}
			}
			if id != "" {
				break
			}
		}
		if id != "" {
			//fmt.Printf("pid %s id %s\n", proc, id)
			nextPidmap[uint32(pid)] = id

			previousId, ok := pm.pidmap[uint32(pid)]
			if !ok || previousId != id {
				pidmapToAdd[uint32(pid)] = id
			}
		}
	}

	for pid, v := range pm.pidmap {
		_, ok := nextPidmap[uint32(pid)]
		if !ok {
			pidmapToRemove[uint32(pid)] = v
		}
	}

	pm.Apply(pidmapToAdd, pidmapToRemove)
	pm.pidmap = nextPidmap
}

func uint32ToHex(v uint32) []string {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, v)

	hexStr := fmt.Sprintf("%02x %02x %02x %02x",
		bytes[0], bytes[1], bytes[2], bytes[3])

	return strings.Split(hexStr, " ")
}

func stringToHex(s string) (out []string) {
	for _, v := range []byte(s) {
		out = append(out, fmt.Sprintf("%02x", byte(v)))
	}
	return
}

func (pm *PidMap) Apply(pidmapToAdd, pidmapToRemove map[uint32]string) {
	if len(pidmapToAdd) == 0 && len(pidmapToRemove) == 0 {
		return
	}
	fmt.Printf("Apply: +%d -%d\n", len(pidmapToAdd), len(pidmapToRemove))
	for k, _ := range pidmapToRemove {
		prog := "bpftool"
		args := []string{
			"map",
			"delete",
			"pinned",
			pidmapPath,
			"key",
			"hex"}
		args = append(args, uint32ToHex(k)...)

		output, err := exec.Command(prog, args...).CombinedOutput()
		if err != nil {
			fmt.Printf("failed to remove from map: %s\n%s", err, output)
			return
		}
	}
	for k, v := range pidmapToAdd {
		prog := "bpftool"
		args := []string{
			"map",
			"update",
			"pinned",
			pidmapPath,
			"key",
			"hex"}
		args = append(args, uint32ToHex(k)...)
		args = append(args, []string{
			"value",
			"hex",
		}...)
		args = append(args, stringToHex(v)...)

		output, err := exec.Command(prog, args...).CombinedOutput()
		if err != nil {
			fmt.Printf("failed to update map: %s\n%s", err, output)
			return
		}
	}
}
