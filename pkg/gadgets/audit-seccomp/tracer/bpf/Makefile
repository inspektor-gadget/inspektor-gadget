.PHONY: all
all:
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go generate ../

clean:
	rm -f ../auditseccomp_bpfel.go ../auditseccomp_bpfel.o ../auditseccompwithfilters_bpfel.go ../auditseccompwithfilters_bpfel.o
