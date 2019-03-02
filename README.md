# k8s-labels-to-bpf

Run the server:
```
sudo -E go run cmd/k8s-labels-to-bpf/k8s-labels-to-bpf.go
```

Watch the map being updated while creating containers:
```
watch bpftool map dump pinned /sys/fs/bpf/pidmap
```
