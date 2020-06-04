package initialcontainers

import (
	"fmt"
	"log"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
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

	nodeSelf := os.Getenv("NODE_NAME")
	node, err := clientset.CoreV1().Nodes().Get(nodeSelf, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed to get node %s", err)
	}

	// get a CRI client to talk to the CRI handling pods in this node
	criClient, err := containerutils.NewCRIClient(node)
	if err != nil {
		return nil, err
	}
	defer criClient.Close()

	// List pods
	pods, err := clientset.CoreV1().Pods("").List(metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeSelf).String(),
	})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		if pod.Spec.NodeName != nodeSelf {
			continue
		}
		labels := []*pb.Label{}
		for k, v := range pod.ObjectMeta.Labels {
			labels = append(labels, &pb.Label{Key: k, Value: v})
		}
		for _, s := range pod.Status.ContainerStatuses {
			if s.ContainerID == "" {
				continue
			}
			if s.State.Running == nil {
				continue
			}

			pid, err := criClient.PidFromContainerId(s.ContainerID)
			if err != nil {
				log.Printf("Skip pod %s/%s: cannot find pid: %v", pod.GetNamespace(), pod.GetName(), err)
				continue
			}
			_, cgroupPathV2, err := containerutils.GetCgroupPaths(pid)
			if err != nil {
				log.Printf("Skip pod %s/%s: cannot find cgroup path: %v", pod.GetNamespace(), pod.GetName(), err)
				continue
			}
			cgroupPathV2WithMountpoint, _ := containerutils.CgroupPathV2AddMountpoint(cgroupPathV2)
			cgroupId, _ := containerutils.GetCgroupID(cgroupPathV2WithMountpoint)
			mntns, err := containerutils.GetMntNs(pid)
			if err != nil {
				log.Printf("Skip pod %s/%s: cannot find mnt namespace: %v", pod.GetNamespace(), pod.GetName(), err)
				continue
			}

			containerDef := pb.ContainerDefinition{
				ContainerId:   s.ContainerID,
				CgroupPath:    cgroupPathV2WithMountpoint,
				CgroupId:      cgroupId,
				Mntns:         mntns,
				Namespace:     pod.GetNamespace(),
				Podname:       pod.GetName(),
				ContainerName: s.Name,
				Labels:        labels,
			}
			arr = append(arr, containerDef)
		}
	}
	return arr, nil
}
