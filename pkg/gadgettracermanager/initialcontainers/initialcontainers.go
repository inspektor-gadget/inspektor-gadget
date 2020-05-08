package initialcontainers

import (
	"log"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils"
)

func InitialContainers() (arr []pb.ContainerDefinition, err error) {
	// Connect to the API server
	kubeconfig := "" // internal access
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	// List pods
	pods, err := clientset.CoreV1().Pods("").List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	nodeSelf := os.Getenv("NODE_NAME")
	for _, pod := range pods.Items {
		if pod.Spec.NodeName != nodeSelf {
			continue
		}
		labels := []*pb.Label{}
		for k, v := range pod.ObjectMeta.Labels {
			labels = append(labels, &pb.Label{Key: k, Value: v})
		}
		for i, s := range pod.Status.ContainerStatuses {
			if s.ContainerID == "" {
				continue
			}
			if s.State.Running == nil {
				continue
			}

			pid, err := containerutils.PidFromContainerId(s.ContainerID)
			if err != nil {
				log.Printf("Skip pod %s/%s: cannot find pid: %v", pod.GetNamespace(), pod.GetName(), err)
				continue
			}
			cgroupPath, err := containerutils.GetCgroup2Path(pid)
			if err != nil {
				log.Printf("Skip pod %s/%s: cannot find cgroup path: %v", pod.GetNamespace(), pod.GetName(), err)
				continue
			}
			cgroupId, err := containerutils.GetCgroupID(cgroupPath)
			if err != nil {
				log.Printf("Skip pod %s/%s: cannot find cgroup id: %v", pod.GetNamespace(), pod.GetName(), err)
				continue
			}

			containerDef := pb.ContainerDefinition{
				ContainerId:    s.ContainerID,
				CgroupPath:     cgroupPath,
				CgroupId:       cgroupId,
				Namespace:      pod.GetNamespace(),
				Podname:        pod.GetName(),
				ContainerIndex: int32(i),
				Labels:         labels,
			}
			arr = append(arr, containerDef)
		}
	}
	return arr, nil
}
