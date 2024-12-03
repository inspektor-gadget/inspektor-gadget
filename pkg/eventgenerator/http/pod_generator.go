package http

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

type PodGenerator struct {
	clientset *kubernetes.Clientset
	config    *rest.Config
	logger    logger.Logger
	namespace string
	podName   string
}

func NewHTTPPodGenerator(config *rest.Config, log logger.Logger) (*PodGenerator, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %w", err)
	}
	return &PodGenerator{
		clientset: clientset,
		config:    config,
		logger:    log,
		namespace: "default",
		podName:   fmt.Sprintf("http-eventgen-pod-%d", time.Now().Unix()),
	}, nil
}

func (h *PodGenerator) Generate(params map[string]string, count int, interval time.Duration) error {
	pods, err := h.clientset.CoreV1().Pods(h.namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing pods: %w", err)
	}

	// Check for existing http-eventgen-pod prefix
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, "http-eventgen-pod-") {
			return fmt.Errorf("HTTP event generator is already running with pod %s, please stop it first", pod.Name)
		}
	}

	url, ok := params["url"]
	if !ok {
		return fmt.Errorf("url parameter is required for HTTP event generator")
	}
	sleepCount := fmt.Sprintf("%.0fs", interval.Seconds())
	command := fmt.Sprintf("i=1; while [ $i -le %d ] || [ %d -eq -1 ]; do curl -s -o /dev/null -w '%%{http_code}\\n' -L %s; i=$((i+1)); sleep %v; done", count, count, url, sleepCount)

	container := corev1.Container{
		Name:    "http-eventgen-container",
		Image:   "alpine/curl",
		Command: []string{"sh", "-c", command},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: h.podName},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers:    []corev1.Container{container},
		},
	}

	_, err = h.clientset.CoreV1().Pods(h.namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating pod: %w", err)
	}

	h.logger.Debugf("Created HTTP event generation pod: %s", h.podName)
	return nil
}

func (h *PodGenerator) Cleanup() (string, error) {
	if h.podName == "" {
		return "", nil
	}
	err := h.clientset.CoreV1().Pods(h.namespace).Delete(context.Background(), h.podName, metav1.DeleteOptions{})
	if err != nil {
		return "", fmt.Errorf("deleting pod %s: %w", h.podName, err)
	}
	h.logger.Debugf("Deleted HTTP event generation pod: %s", h.podName)
	h.podName = "" // Reset the podName after cleanup
	return "", nil
}
