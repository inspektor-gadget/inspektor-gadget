# Demo

## Install Kubernetes on Flatcar Linux

TODO

## Enable cgroup-v2

### Enable cgroup-v2 in grub

To enable the hybrid mode on Flatcar Linux:
- `sudo vi /usr/share/oem/grub.cfg`
- `set linux_append="...... systemd.unified_cgroup_hierarchy=false systemd.legacy_systemd_cgroup_controller=false"`
- `sudo reboot`

### Enable cgroup-v2 in Docker

```
$ echo 'DOCKER_OPTS="--exec-opt native.cgroupdriver=systemd"' |  sudo tee -a /run/metadata/torcx
```
Or alternatively:
```
$ sudo mkdir  /etc/systemd/system/docker.service.d
$ printf '[Service]\nEnvironment=DOCKER_OPTS="--exec-opt native.cgroupdriver=systemd"\n' | sudo tee /etc/systemd/system/docker.service.d/10-docker.conf
```
And then:
```
$ sudo systemctl daemon-reload
$ sudo systemctl restart docker
$ sudo docker run -ti --rm busybox cat /proc/self/cgroup |grep ^[01]:
1:name=systemd:/system.slice/docker-5631ac3634cfd17a2ae5d9068c4121fbe2f392020b9db3d780e571c6b8954db3.scope
0::/system.slice/docker-5631ac3634cfd17a2ae5d9068c4121fbe2f392020b9db3d780e571c6b8954db3.scope
```

### Enable cgroup-v2 in Kubelet

If you use the `kubelet` on the node, ensure it is started with `--cgroup-driver=systemd`:
```
sudo vim /etc/systemd/system/kubelet.service
...
```

### Enable cgroup-v2 in containerd

If you use `containerd` on the node, you need:
```
sudo mount -o remount,rw /run/torcx/unpack/
printf '\n\n[plugins.cri]\nsystemd_cgroup = true\n' | sudo tee -a /run/torcx/unpack/docker/usr/share/containerd/config.toml
sudo sed -i 's/^disabled_plugins.*$/disabled_plugins = []/g' /run/torcx/unpack/docker/usr/share/containerd/config.toml
sudo systemctl restart containerd
```
(it will work for processes started in the container, but not for processes entering via `kubectl exec` since containerd will not setup the cgroup-v2 there)

## Install bpftool

```
docker run --privileged -v /tmp:/out albanc/bcck8s cp /bin/bpftool /out/
sudo mkdir -p /opt/bin
sudo cp /tmp/bpftool /opt/bin/
```

## Install cgroupid

```
docker run --privileged -v /tmp:/out albanc/cgroupid cp /bin/cgroupid /out/
sudo mkdir -p /opt/bin
sudo cp /tmp/cgroupid /opt/bin/
```

## Install kubectl

```
sudo mkdir -p /opt/bin
cd /opt/bin/
curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
chmod +x kubectl
```

## Install the OCI PreStart Hook

```
scp $GOPATH/src/github.com/opencontainers/runc/runc-hook-prestart-static realedge-w1:/tmp/
scp $GOPATH/src/github.com/opencontainers/runc/runc-hook-prestart-static realedge-w2:/tmp/
```

On each node:
```
sudo mount -o remount,rw /run/torcx/unpack/
cd /run/torcx/unpack/docker/bin/
sudo cp /tmp/runc-hook-prestart-static ./
sudo cp runc runc.bak
sudo cp runc-hook-prestart-static runc
```

Prepare:
```
scp ./runc-hook-prestart.sh realedge-w1:/tmp/runc-hook-prestart.sh
scp ./runc-hook-prestart.sh realedge-w2:/tmp/runc-hook-prestart.sh
```

## Demo

```
export KUBECONFIG=.../kubeconfig
```

```
$ kubectl cp execsnoop-edge bcck8s-shell-nqx5p:/execsnoop-edge
$ kubectl exec -ti bcck8s-shell-nqx5p -- /execsnoop-edge --label myapp=app-one
PCOMM            PID    PPID   RET ARGS
pause            1273   1236     0 /pause
sh               1833   1803     0 /usr/bin/sh -c while /bin/true ; do date ; cat /proc/version ; sleep 1 ; done
true             1974   1833     0 /bin/true
date             1975   1833     0 /usr/bin/date
cat              1976   1833     0 /usr/bin/cat /proc/version
sleep            1977   1833     0 /usr/bin/sleep 1
true             1988   1833     0 /bin/true
date             1989   1833     0 /usr/bin/date
cat              1990   1833     0 /usr/bin/cat /proc/version
sleep            1991   1833     0 /usr/bin/sleep 1

```

