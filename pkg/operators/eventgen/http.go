package eventgen

import (
    "context"
    "fmt"
    "strings"
    "time"

    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/kubernetes/scheme"
    "k8s.io/client-go/rest"
    "k8s.io/client-go/tools/remotecommand"
)

type HTTPGenerator struct {
    clientset *kubernetes.Clientset
    config    *rest.Config
}

func NewHTTPGenerator(config *rest.Config) (Generator, error) {
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
    }
    return &HTTPGenerator{
        clientset: clientset,
        config:    config,
    }, nil
}

func (h *HTTPGenerator) Generate(url string) (string, error) {
    namespace := "default"
    podName := fmt.Sprintf("http-test-pod-%d", time.Now().Unix())

    if err := h.createAndWaitForPod(namespace, podName); err != nil {
        return "", fmt.Errorf("failed to create and wait for pod: %v", err)
    }

    if err := h.executeHTTPRequest(namespace, podName, url); err != nil {
        return "", fmt.Errorf("failed to execute HTTP request: %v", err)
    }

    return podName, nil
}

func (h *HTTPGenerator) Cleanup(podName string) error {
    namespace := "default"
    err := h.clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
    if err != nil {
        return fmt.Errorf("failed to delete pod %s: %v", podName, err)
    }
    return nil
}

func (h *HTTPGenerator) createAndWaitForPod(namespace, name string) error {
    pod := &corev1.Pod{
        ObjectMeta: metav1.ObjectMeta{Name: name},
        Spec: corev1.PodSpec{
            Containers: []corev1.Container{{
                Name:    "http-test",
                Image:   "alpine/curl",
                Command: []string{"sleep", "3600"},
            }},
        },
    }

    _, err := h.clientset.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
    if err != nil {
        return fmt.Errorf("failed to create pod: %v", err)
    }

    for i := 0; i < 60; i++ {
        pod, err := h.clientset.CoreV1().Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
        if err != nil {
            return err
        }
        if pod.Status.Phase == corev1.PodRunning {
            return nil
        }
        time.Sleep(time.Second)
    }
    return fmt.Errorf("pod did not become ready within 60 seconds")
}

func (h *HTTPGenerator) executeHTTPRequest(namespace, podName, url string) error {
    cmd := []string{"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L", url}
    stdout, stderr, err := h.executeCommand(namespace, podName, cmd)
    if err != nil {
        return fmt.Errorf("failed to execute command: %v\nStderr: %s", err, stderr)
    }

    statusCode := strings.TrimSpace(stdout)
    if statusCode == "200" {
        return nil
    }

    return fmt.Errorf("HTTP request failed with status code: %s", statusCode)
}

func (h *HTTPGenerator) executeCommand(namespace, podName string, command []string) (string, string, error) {
    req := h.clientset.CoreV1().RESTClient().Post().
        Resource("pods").
        Name(podName).
        Namespace(namespace).
        SubResource("exec").
        VersionedParams(&corev1.PodExecOptions{
            Command: command,
            Stdout:  true,
            Stderr:  true,
        }, scheme.ParameterCodec)

    exec, err := remotecommand.NewSPDYExecutor(h.config, "POST", req.URL())
    if err != nil {
        return "", "", fmt.Errorf("failed to create executor: %v", err)
    }

    var stdout, stderr strings.Builder
    err = exec.Stream(remotecommand.StreamOptions{
        Stdout: &stdout,
        Stderr: &stderr,
    })

    return stdout.String(), stderr.String(), err
}