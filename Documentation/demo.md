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
docker run --rm --privileged -v /tmp:/out albanc/bcck8s cp /bin/bpftool /out/
sudo mkdir -p /opt/bin
sudo cp /tmp/bpftool /opt/bin/
```

## Install cgroupid

```
docker run --rm --privileged -v /tmp:/out albanc/cgroupid cp /bin/cgroupid /out/
sudo mkdir -p /opt/bin
sudo cp /tmp/cgroupid /opt/bin/
```

## Install kubectl

```
sudo mkdir -p /opt/bin
cd /opt/bin/
sudo curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
sudo chmod +x kubectl
```

## Install the OCI PreStart Hook

runc is recompiled with
```
make COMMIT_NO= BUILDTAGS="seccomp selinux apparmor"
cp runc runc-static-hooks

scp $GOPATH/src/github.com/opencontainers/runc/runc-static-hooks realedge-w1:/tmp/
scp $GOPATH/src/github.com/opencontainers/runc/runc-static-hooks realedge-w2:/tmp/
```

On each node:
```
sudo mount -o remount,rw /run/torcx/unpack/
cd /run/torcx/unpack/docker/bin/
sudo cp /tmp/runc-static-hooks ./
sudo cp runc runc.bak
sudo cp runc-static-hooks runc
```

Prepare:
```
scp ./runc-hook-prestart.sh realedge-w1:/tmp/runc-hook-prestart.sh
scp ./runc-hook-prestart.sh realedge-w2:/tmp/runc-hook-prestart.sh
```

On each node:
```
sudo mv -i  /tmp/runc-hook-prestart.sh /opt/bin/runc-hook-prestart.sh
```

## Demo

```
export KUBECONFIG=.../kubeconfig
```

```
kubectl apply -f break.yaml
kubectl apply -f ds-privileged.yaml
kubectl apply -f ds-myapp.yaml
kubectl apply -f ds-bcck8s.yaml
kubectl apply -f ds-straceback.yaml
```

```
$ make install
$ make install-hooks

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

## Demo straceback 1

With straceback, we can strace pods in the past, even after they terminated.

Example: let's list the programs in /bin:
```
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'ls -l /bin | grep wget'
-rwxr-xr-x  395 root     root       1120520 Apr  2 04:32 wget
$ kubectl delete pod mypod
pod "mypod" deleted
```

Because of the `grep wget`, we only see one entry. But straceback can recover other entries:

```
$ ./gadget-straceback.sh list | grep mypod
10.0.13.143_default_mypod
$ ./gadget-straceback.sh show 10.0.18.186_default_mypod | grep /bin/w
00:00.063359811 cpu#1 pid 23855 [ls] newfstatat(dfd=18446744073709551516, filename=15904080 "/bin/wc", statbuf=140733574659888, flag=256) = 0
00:00.064064654 cpu#1 pid 23855 [ls] newfstatat(dfd=18446744073709551516, filename=15909120 "/bin/who", statbuf=140733574659888, flag=256) = 0
00:00.064507308 cpu#1 pid 23855 [ls] newfstatat(dfd=18446744073709551516, filename=15911856 "/bin/which", statbuf=140733574659888, flag=256) = 0
00:00.068681797 cpu#0 pid 23855 [ls] newfstatat(dfd=18446744073709551516, filename=15933456 "/bin/w", statbuf=140733574659888, flag=256) = 0
00:00.069013385 cpu#0 pid 23855 [ls] newfstatat(dfd=18446744073709551516, filename=15935616 "/bin/wall", statbuf=140733574659888, flag=256) = 0
00:00.069698145 cpu#0 pid 23855 [ls] newfstatat(dfd=18446744073709551516, filename=15941664 "/bin/wget", statbuf=140733574659888, flag=256) = 0
00:00.070749979 cpu#0 pid 23855 [ls] newfstatat(dfd=18446744073709551516, filename=15950448 "/bin/whoami", statbuf=140733574659888, flag=256) = 0
00:00.071240372 cpu#0 pid 23855 [ls] newfstatat(dfd=18446744073709551516, filename=15954192 "/bin/watch", statbuf=140733574659888, flag=256) = 0
00:00.071303433 cpu#0 pid 23855 [ls] newfstatat(dfd=18446744073709551516, filename=15954768 "/bin/whois", statbuf=140733574659888, flag=256) = 0
00:00.071700065 cpu#0 pid 23855 [ls] newfstatat(dfd=18446744073709551516, filename=15958080 "/bin/watchdog", statbuf=140733574659888, flag=256) = 0
```

## Demo straceback 2

Let's run a pod to compute an important multiplication:
```
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'RANDOM=output ; echo "3*7*2" | bc > /tmp/file-$RANDOM ; cat /tmp/file-$RANDOM'
cat: can't open '/tmp/file-7071': No such file or directory
pod default/mypod terminated (Error)
```

Oh no! We made a mistake in the shell script: we opened the wrong file. Is the result lost forever? Let's check with the straceback gadget:

```
$ ./gadget-straceback.sh list | grep mypod
10.0.18.186_default_mypod
```

Let's inspect the straceback log:

```
$ ./gadget-straceback.sh show 10.0.18.186_default_mypod|grep -E 'write|/tmp/file'
00:00.002167734 cpu#0 pid 30908 [runc:[2:INIT]] write(fd=4, buf=824634358208 "{\"type\":\"procReady\"}", count=20)...
00:00.002184497 cpu#0 pid 30908 [runc:[2:INIT]] ...write() = 20
00:00.002299731 cpu#0 pid 30908 [runc:[2:INIT]] write(fd=3, buf=824634232096 "system_u:system_r:svirt_lxc_net_t:s0:c85,c812", count=45) = 45
00:00.066281152 cpu#0 pid 30908 [runc:[2:INIT]] write(fd=3, buf=824634954112 "0", count=1) = 1
00:00.068550385 cpu#0 pid 31021 [sh] write(fd=1, buf=34788528 "3*7*2\n", count=6)...
00:00.068580369 cpu#0 pid 31021 [sh] ...write() = 6
00:00.068748841 cpu#1 pid 31022 [sh] open(filename=34788736 "/tmp/file-32298", flags=577, mode=438) = 3
00:00.069271334 cpu#0 pid 31022 [bc] write(fd=1, buf=7415808 "42\n", count=3) = 3
00:00.070597676 cpu#1 pid 30908 [cat] open(filename=140729712668244 "/tmp/file-12508", flags=0, mode=0) = 18446744073709551614
00:00.070634288 cpu#1 pid 30908 [cat] write(fd=2, buf=140729712660992 "cat: can't open '/tmp/file-12508': No such file or directory\n", count=61) = 61
```

Thanks to the `straceback` gadget, we can recover the result of the multiplication: 42. And we can understand the mistake in the shell script: the result was saved in `/tmp/file-32298` but we attempted to open `/tmp/file-12508`.
