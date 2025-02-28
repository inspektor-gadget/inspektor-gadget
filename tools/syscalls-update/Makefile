all: syscalls-update
	./syscalls-update

syscalls-update: main.go syscalls_arch.go.tmpl
	go build -o syscalls-update main.go