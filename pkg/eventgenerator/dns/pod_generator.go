package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type PodGenerator struct {
	clientset *kubernetes.Clientset
	config    *rest.Config
	logger    logger.Logger
	namespace string
	podName   string
}

func NewDNSPodGenerator(config *rest.Config, log logger.Logger) (*PodGenerator, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %w", err)
	}

	return &PodGenerator{
		clientset: clientset,
		config:    config,
		logger:    log,
		namespace: "default",
		podName:   fmt.Sprintf("dns-eventgen-pod-%d", time.Now().Unix()),
	}, nil
}

func (d *PodGenerator) Generate(params map[string]string, count int, interval time.Duration) error {
	d.logger.Debugf("Starting pod generation with params: %v", params)

	pods, err := d.clientset.CoreV1().Pods(d.namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing pods: %w", err)
	}

	// Check for existing dns-eventgen pods
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, "dns-eventgen-pod-") {
			return fmt.Errorf("DNS event generator is already running with pod %s, please stop it first", pod.Name)
		}
	}

	domain, ok := params["domain"]
	if !ok {
		return fmt.Errorf("domain parameter is required for DNS event generation")
	}

	d.logger.Debugf("Creating new pod with name: %s", d.podName)

	sleepCount := fmt.Sprintf("%.0fs", interval.Seconds())
	command := fmt.Sprintf("i=1; while [ $i -le %d ] || [ %d -eq -1 ]; do nslookup %s; i=$((i+1)); sleep %s; done",
		count, count, domain, sleepCount)

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

	d.logger.Debugf("Creating pod with command: %s", command)

	_, err = d.clientset.CoreV1().Pods(d.namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating pod: %w", err)
	}

	d.logger.Debugf("Successfully created DNS event generation pod: %s", d.podName)
	return nil
}

func (d *PodGenerator) Cleanup() (string, error) {
	if d.podName == "" {
		return "", nil
	}

	err := d.clientset.CoreV1().Pods(d.namespace).Delete(context.Background(), d.podName, metav1.DeleteOptions{})
	if err != nil {
		return "", fmt.Errorf("deleting pod %s: %w", d.podName, err)
	}

	d.logger.Debugf("Successfully terminated DNS event generation pod: %s", d.podName)
	d.podName = ""
	return "", nil
}
