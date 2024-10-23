package http

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Generator struct {
	clientset *kubernetes.Clientset
	config    *rest.Config
	logger    logger.Logger
	namespace string
	podName   string
}

func NewGenerator(config *rest.Config, log logger.Logger) (*Generator, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}
	return &Generator{
		clientset: clientset,
		config:    config,
		logger:    log,
		namespace: "default",
		podName:   fmt.Sprintf("http-eventgen-pod-%d", time.Now().Unix()),
	}, nil
}

func (h *Generator) Generate(url, countStr, intervalStr string) (string, string, string, error) {
	count, err := strconv.Atoi(countStr)
	if err != nil {
		count = -1
	}

	interval, err := strconv.ParseFloat(intervalStr, 64)
	if err != nil || interval <= 0 {
		interval = 1
	}

	command := fmt.Sprintf("i=1; while [ $i -le %d ] || [ %d -eq -1 ]; do curl -s -o /dev/null -w '%%{http_code}\\n' -L %s; i=$((i+1)); sleep %f; done", count, count, url, interval)

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
		return "", "", "", fmt.Errorf("failed to create pod: %v", err)
	}

	h.logger.Debugf("Created HTTP event generation pod: %s", h.podName)
	return h.namespace, h.podName, container.Name, nil
}

func (h *Generator) Cleanup() (string, error) {
	if h.podName == "" {
		return "", fmt.Errorf("pod %s is not found in %s namespace", h.podName, h.namespace)
	}
	err := h.clientset.CoreV1().Pods(h.namespace).Delete(context.Background(), h.podName, metav1.DeleteOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to delete pod %s: %v", h.podName, err)
	}
	h.logger.Debugf("Deleted HTTP event generation pod: %s", h.podName)
	h.podName = "" // Reset the podName after cleanup
	return "", nil
}