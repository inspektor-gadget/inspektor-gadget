package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	_ "net/http/pprof"

	"github.com/dustin/go-humanize"
	v1 "k8s.io/api/core/v1"

	//metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	new "github.com/inspektor-gadget/inspektor-gadget/foo/podinformercomparison/new"
	old "github.com/inspektor-gadget/inspektor-gadget/foo/podinformercomparison/old"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

type PodInformer interface {
	DeletedChan() <-chan string
	UpdatedChan() <-chan *v1.Pod
	//func Run(threadiness int, stopCh chan struct{})
	//Stop()
}

func printMemory() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc : %s\n", humanize.Bytes(m.Alloc))
}

func do() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: old/new json/proto")
	}

	config, err := k8sutil.NewKubeConfig("")
	if err != nil {
		return fmt.Errorf("creating new k8s clientset: %w", err)
	}

	switch os.Args[2] {
	case "json":
		config.ContentType = "application/json"
	case "proto":
		config.ContentType = "application/vnd.kubernetes.protobuf"
	default:
		return fmt.Errorf("invalid argument: %s", os.Args[2])
	}

	var podInformer PodInformer
	switch os.Args[1] {
	case "old":
		podInformer, err = old.NewPodInformer(config)
	case "new":
		podInformer, err = new.NewPodInformer(config)
	default:
		return fmt.Errorf("invalid argument: %s", os.Args[1])
	}
	if err != nil {
		return err
	}

	i := 0

	go func() {
		for {
			select {
			case _, ok := <-podInformer.DeletedChan():
				if !ok {
					return //nil
				}
				//fmt.Printf("pod %s was deleted\n", key)
			case _, ok := <-podInformer.UpdatedChan():
				if !ok {
					return //nil
				}
				//fmt.Printf("%d) pod %s was updated\n", i, pod.Name)
				i++
			}
		}
	}()

	time.Sleep(5 * time.Second)
	fmt.Printf("there are %d pods\n", i)

	runtime.GC()
	printMemory()

	// wait for enter
	fmt.Println("Press enter to exit")
	fmt.Scanln()

	return nil
}

func main() {
	// enable http server
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	if err := do(); err != nil {
		fmt.Println(err)
	}
}
