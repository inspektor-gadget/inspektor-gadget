package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/weaveworks/tcptracer-bpf/pkg/tracer"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/networkpolicy/types"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var (
	cgroupmap     string
	namespaceList string
	namespaceSet  map[string]struct{}
	kubeconfig    string
)

func init() {
	flag.StringVar(&cgroupmap, "cgroupmap", "", "path to a BPF map containing a cgroup set")
	flag.StringVar(&namespaceList, "namespace", "", "comma-separated list of namespaces")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "path to a kubeconfig")
}

type tcpEventTracer struct {
	clientset *kubernetes.Clientset
	queue     chan tracer.TcpV4
}

func (t *tcpEventTracer) TCPEventV4(e tracer.TcpV4) {
	if e.Type == tracer.EventFdInstall {
		return
	}
	if e.Type == tracer.EventClose {
		return
	}
	t.queue <- e
}

func (t *tcpEventTracer) handleEvent(e tracer.TcpV4, pods *corev1.PodList, svcs *corev1.ServiceList) {
	var event types.KubernetesConnectionEvent
	event.Type = e.Type.String()
	if e.Type == tracer.EventAccept {
		event.Port = e.SPort
	} else {
		event.Port = e.DPort
	}

	event.Debug = fmt.Sprintf("%v cpu#%d %s %v %s %v:%v %v:%v %v\n",
		e.Timestamp, e.CPU, e.Type, e.Pid, e.Comm, e.SAddr, e.SPort, e.DAddr, e.DPort, e.NetNS)

	localPodIndex := -1
	for i, pod := range pods.Items {
		if pod.Status.PodIP == e.SAddr.String() {
			if _, ok := namespaceSet[pod.Namespace]; ok {
				localPodIndex = i
				event.LocalPodNamespace = pod.Namespace
				event.LocalPodName = pod.Name
				event.LocalPodLabels = pod.Labels
			}
		}
		if pod.Status.PodIP == e.DAddr.String() {
			event.RemoteKind = "pod"
			event.RemotePodNamespace = pod.Namespace
			event.RemotePodName = pod.Name
			event.RemotePodLabels = pod.Labels
		}
	}
	if event.LocalPodName == "" {
		return
	}

	/* When the pod belong to Deployment, ReplicaSet or DaemonSet, find the
	 * shorter name without the random suffix. That will be used to
	 * generate the network policy name. */
	if pods.Items[localPodIndex].OwnerReferences != nil {
		nameItems := strings.Split(event.LocalPodName, "-")
		if len(nameItems) > 2 {
			event.LocalPodOwner = strings.Join(nameItems[:len(nameItems)-2], "-")
		}
	}

	if event.RemoteKind == "" {
		for _, svc := range svcs.Items {
			if svc.Spec.ClusterIP == e.DAddr.String() {
				event.RemoteKind = "svc"
				event.RemoteSvcNamespace = svc.Namespace
				event.RemoteSvcName = svc.Name
				event.RemoteSvcLabelSelector = svc.Spec.Selector
				break
			}
		}
	}
	if event.RemoteKind == "" {
		event.RemoteKind = "other"
		event.RemoteOther = e.DAddr.String()
	}

	buf, err := json.Marshal(event)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	fmt.Printf("%s\n", string(buf))
}

func (t *tcpEventTracer) TCPEventV6(e tracer.TcpV6) {
	if e.Type == tracer.EventFdInstall {
		return
	}
	if e.Type == tracer.EventClose {
		return
	}
}

func (t *tcpEventTracer) LostV4(count uint64) {
	fmt.Printf("ERROR: lost %d events!\n", count)
}

func (t *tcpEventTracer) LostV6(count uint64) {
	fmt.Printf("ERROR: lost %d events!\n", count)
}

func main() {
	// Parse arguments
	flag.Parse()
	if flag.NArg() > 0 {
		flag.PrintDefaults()
		panic(fmt.Errorf("invalid command"))
	}
	namespaceSet = make(map[string]struct{})
	for _, item := range strings.Split(namespaceList, ",") {
		namespaceSet[item] = struct{}{}
	}

	// Connect to the API server
	clientset, err := k8sutil.NewClientset(kubeconfig)
	if err != nil {
		panic(err)
	}

	// Start the BPF tracer
	mytracer := &tcpEventTracer{
		clientset: clientset,
		queue:     make(chan tracer.TcpV4, 500),
	}
	t, err := tracer.NewTracer(mytracer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	ticker := time.NewTicker(time.Second)
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				eventCount := len(mytracer.queue)
				if eventCount == 0 {
					continue
				}
				// Consume that amount of events from the queue and use the same cache of
				// pods and services with them. We might not consume all the events,
				// that's ok, we'll get them at the next tick.
				batch := make([]tracer.TcpV4, eventCount)
				for i := 0; i < eventCount; i++ {
					batch[i] = <-mytracer.queue
				}
				pods, err := clientset.CoreV1().Pods("").List(metav1.ListOptions{})
				if err != nil {
					fmt.Printf("Error: %s\n", err)
					return
				}
				svcs, err := clientset.CoreV1().Services("").List(metav1.ListOptions{})
				if err != nil {
					fmt.Printf("Error: %s\n", err)
					return
				}
				for _, e := range batch {
					mytracer.handleEvent(e, pods, svcs)
				}
			}
		}
	}()

	t.Start()
	fmt.Printf(`{"type":"ready"}` + "\n")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig

	t.Stop()
	ticker.Stop()
	done <- true
}
