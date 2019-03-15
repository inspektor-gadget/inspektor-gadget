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

## Install the OCI PreStart Hook

```
scp ./runc-hook-prestart-static albandemo-w1:/tmp/
scp ./runc-hook-prestart-static albandemo-w2:/tmp/
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
scp ./runc-hook-prestart.sh albandemo-w1:/tmp/runc-hook-prestart.sh
scp ./runc-hook-prestart.sh albandemo-w2:/tmp/runc-hook-prestart.sh
```
