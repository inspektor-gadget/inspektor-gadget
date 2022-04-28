.PHONY: all
all:
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go generate ../

clean:
	rm -f ../processcollector_bpfel.go ../processcollector_bpfel.o ../processcollectorwithfilters_bpfel.go ../processcollectorwithfilters_bpfel.o
