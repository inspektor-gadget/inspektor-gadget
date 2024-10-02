package eventgen

import (
    "bytes"
    "context"
    "fmt"
    "time"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/kubernetes/scheme"
    "k8s.io/client-go/rest"
    "k8s.io/client-go/tools/remotecommand"
)

type DNSGenerator struct {
    clientset *kubernetes.Clientset
    config    *rest.Config
}

func NewDNSGenerator(config *rest.Config) (Generator, error) {
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
    }
    return &DNSGenerator{
        clientset: clientset,
        config:    config,
    }, nil
}

func (d *DNSGenerator) Generate(domain string) (string, error) {
    namespace := "default"
    podName := fmt.Sprintf("dns-test-pod-%d", time.Now().Unix())

    if err := d.createAndWaitForPod(namespace, podName); err != nil {
        return "", err
    }

    if err := d.executeDNSLookup(namespace, podName, domain); err != nil {
        return "", err
    }

    return podName, nil
}

func (d *DNSGenerator) Cleanup(podName string) error {
    namespace := "default"
    err := d.clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
    if err != nil {
        return fmt.Errorf("failed to delete pod %s: %v", podName, err)
    }
    fmt.Printf("Successfully deleted pod %s in namespace %s\n", podName, namespace)
    return nil
}

func (d *DNSGenerator) createAndWaitForPod(namespace, name string) error {
    pod := &corev1.Pod{
        ObjectMeta: metav1.ObjectMeta{Name: name},
        Spec: corev1.PodSpec{
            Containers: []corev1.Container{{
                Name:    "dns-test",
                Image:   "busybox",
                Command: []string{"sh", "-c", "while true; do sleep 3600; done"},
            }},
        },
    }

    _, err := d.clientset.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
    if err != nil {
        return fmt.Errorf("failed to create pod: %v", err)
    }

    for i := 0; i < 60; i++ {
        pod, err := d.clientset.CoreV1().Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
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

func (d *DNSGenerator) executeDNSLookup(namespace, podName, domain string) error {
    req := d.clientset.CoreV1().RESTClient().Post().
        Resource("pods").
        Name(podName).
        Namespace(namespace).
        SubResource("exec").
        VersionedParams(&corev1.PodExecOptions{
            Command: []string{"sh", "-c", fmt.Sprintf("echo 'Performing DNS lookup for %s'; nslookup %s; echo 'DNS lookup completed'", domain, domain)},
            Stdout:  true,
            Stderr:  true,
        }, scheme.ParameterCodec)

    exec, err := remotecommand.NewSPDYExecutor(d.config, "POST", req.URL())
    if err != nil {
        return fmt.Errorf("failed to create executor: %v", err)
    }

    var stdout, stderr bytes.Buffer
    err = exec.Stream(remotecommand.StreamOptions{
        Stdout: &stdout,
        Stderr: &stderr,
    })
    if err != nil {
        return fmt.Errorf("failed to execute command: %v", err)
    }

    fmt.Printf("DNS lookup output:\n%s\n", stdout.String())
    if stderr.Len() > 0 {
        fmt.Printf("DNS lookup error:\n%s\n", stderr.String())
    }

    return nil
}