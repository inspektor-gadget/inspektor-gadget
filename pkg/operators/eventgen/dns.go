package eventgen

import (
	"context"
	"fmt"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

type DNSGenerator struct {
	clientset *kubernetes.Clientset
	config    *rest.Config
	logger    logger.Logger
	namespace string
	podName   string
}

func NewDNSGenerator(config *rest.Config, log logger.Logger) (Generator, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}
	return &DNSGenerator{
		clientset: clientset,
		config:    config,
		logger:    log,
		namespace: "default",
		podName:   fmt.Sprintf("dns-eventgen-pod-%d", time.Now().Unix()),
	}, nil
}

func (d *DNSGenerator) Generate(domain, countStr, intervalStr string) (string, string, string, error) {
	count, err := strconv.Atoi(countStr)
	if err != nil {
		count = -1 // Default to infinite if not specified or invalid
	}

	interval, err := strconv.ParseFloat(intervalStr, 64)
	if err != nil || interval <= 0 {
		interval = 1 // Default to 1 second if not specified or invalid
	}
	// *TODO: discussion on cleanup after executing event if count is set?
	command := fmt.Sprintf("i=1; while [ $i -le %d ] || [ %d -eq -1 ]; do nslookup %s; i=$((i+1)); sleep %f; done", count, count, domain, interval)

	container := corev1.Container{
		Name:    "dns-eventgen-container",
		Image:   "busybox",
		Command: []string{"sh", "-c", command},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: d.podName},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers:    []corev1.Container{container},
		},
	}

	_, err = d.clientset.CoreV1().Pods(d.namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create pod: %v", err)
	}

	d.logger.Debugf("Created DNS event generation pod: %s", d.podName)
	return d.namespace, d.podName, container.Name, nil
}

func (d *DNSGenerator) Cleanup() (string, error) {
	if d.podName == "" {
		return "", fmt.Errorf("pod %s is not found in %s namespace", d.podName, d.namespace)
	}
	err := d.clientset.CoreV1().Pods(d.namespace).Delete(context.Background(), d.podName, metav1.DeleteOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to delete pod %s: %v", d.podName, err)
	}
	d.logger.Debugf("Deleted DNS event generation pod: %s", d.podName)
	d.podName = "" // Reset the podName after cleanup
	return "", nil
}
