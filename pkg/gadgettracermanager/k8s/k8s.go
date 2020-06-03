package k8s

import (
	"fmt"
	"os"
	"strings"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
)

// FillContainer uses the k8s API server to get the pod name, namespace,
// labels and container index for the given container.
func FillContainer(containerDefinition *pb.ContainerDefinition) error {
	// Get details of the container from the k8s API server
	clientset, err := k8sutil.NewClientset("")
	if err != nil {
		return err
	}

	nodeSelf := os.Getenv("NODE_NAME")
	pods, err := clientset.CoreV1().Pods("").List(metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeSelf).String(),
	})
	if err != nil {
		return err
	}

	cgroupPathV1 := containerDefinition.CgroupV1
	cgroupPathV2 := containerDefinition.CgroupV2

	namespace := ""
	podname := ""
	containerIndex := -1
	labels := []*pb.Label{}
	for _, pod := range pods.Items {
		uid := string(pod.ObjectMeta.UID)
		// check if this container is associated to this pod
		uidWithUnderscores := strings.ReplaceAll(uid, "-", "_")

		if !strings.Contains(cgroupPathV2, uidWithUnderscores) &&
			!strings.Contains(cgroupPathV2, uid) &&
			!strings.Contains(cgroupPathV1, uidWithUnderscores) &&
			!strings.Contains(cgroupPathV1, uid) {
			continue
		}

		namespace = pod.ObjectMeta.Namespace
		podname = pod.ObjectMeta.Name

		for k, v := range pod.ObjectMeta.Labels {
			labels = append(labels, &pb.Label{Key: k, Value: v})
		}
		for i, container := range pod.Spec.Containers {
			for _, mountSource := range containerDefinition.MountSources {
				pattern := fmt.Sprintf("pods/%s/containers/%s/", uid, container.Name)
				if strings.Contains(mountSource, pattern) {
					containerIndex = i
					break
				}
			}
		}
	}

	containerDefinition.Namespace = namespace
	containerDefinition.Podname = podname
	containerDefinition.ContainerIndex = int32(containerIndex)
	containerDefinition.Labels = labels

	return nil
}
