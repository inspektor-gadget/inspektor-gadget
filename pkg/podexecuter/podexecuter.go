// Inspired from
// https://github.com/iovisor/kubectl-trace/blob/e4bfc999828cdd45830fdbf1853b096035ad8349/pkg/attacher/attach.go

package podexecuter

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"time"

	//"github.com/iovisor/kubectl-trace/pkg/meta"
	//"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	tcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/kubernetes/pkg/kubectl/util/term"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type PodExecuter struct {
	genericclioptions.IOStreams
	ctx          context.Context
	CoreV1Client tcorev1.CoreV1Interface
	Config       *restclient.Config
}

func NewPodExecuter(client tcorev1.CoreV1Interface, config *restclient.Config, streams genericclioptions.IOStreams) *PodExecuter {
	return &PodExecuter{
		CoreV1Client: client,
		Config:       config,
		ctx:          context.TODO(),
		IOStreams:    streams,
	}
}

const (
	podNotFoundError              = "no pod found to exec with the given selector"
	podPhaseNotAcceptedError      = "cannot exec into a container in a completed pod; current phase is %s"
	invalidPodContainersSizeError = "unexpected number of containers in trace job pod"
)

func (a *PodExecuter) WithContext(c context.Context) {
	a.ctx = c
}

func (a *PodExecuter) Exec(selector, namespace string) {
	go wait.ExponentialBackoff(wait.Backoff{
		Duration: time.Second * 1,
		Factor:   0.01,
		Jitter:   0.0,
		Steps:    100,
	}, func() (bool, error) {
		pl, err := a.CoreV1Client.Pods(namespace).List(metav1.ListOptions{
			LabelSelector: selector,
		})

		if err != nil {
			return false, err
		}

		if len(pl.Items) == 0 {
			return false, fmt.Errorf(podNotFoundError)
		}
		pod := &pl.Items[0]
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			return false, fmt.Errorf(podPhaseNotAcceptedError, pod.Status.Phase)
		}

		if len(pod.Spec.Containers) != 1 {
			return false, fmt.Errorf(invalidPodContainersSizeError)
		}

		restClient := a.CoreV1Client.RESTClient().(*restclient.RESTClient)
		containerName := pod.Spec.Containers[0].Name

		t, err := setupTTY(a.IOStreams.Out, a.IOStreams.In)
		if err != nil {
			return false, err
		}
		ao := exec{
			restClient:    restClient,
			podName:       pod.Name,
			namespace:     pod.Namespace,
			containerName: containerName,
			config:        a.Config,
			tty:           t,
		}
		err = t.Safe(ao.defaultExecFunc())

		if err != nil {
			// on error, just send false so that the backoff mechanism can do a new tentative
			return false, nil
		}
		return true, nil
	})
	<-a.ctx.Done()
}

type exec struct {
	restClient    *restclient.RESTClient
	podName       string
	containerName string
	namespace     string
	config        *restclient.Config
	tty           term.TTY
}

func (a exec) defaultExecFunc() func() error {
	return func() error {
		req := a.restClient.Post().
			Resource("pods").
			Name(a.podName).
			Namespace(a.namespace).
			SubResource("exec")
		req.VersionedParams(&corev1.PodExecOptions{
			Container: a.containerName,
			Stdin:     true,
			Stdout:    true,
			Stderr:    false,
			TTY:       a.tty.Raw,
		}, scheme.ParameterCodec)

		att := &defaultRemoteExec{}

		//// since the TTY is always in raw mode when execing do a fake resize
		//// of the screen so that it will be redrawn during exec and detach
		//tsize := a.tty.GetSize()
		var terminalSizeQueue remotecommand.TerminalSizeQueue
		//if tsize != nil {
		//	tsizeinc := *tsize
		//	tsizeinc.Height++
		//	tsizeinc.Width++
		//	terminalSizeQueue = a.tty.MonitorSize(&tsizeinc, tsize)
		//}

		return att.Exec("POST", req.URL(), a.config, a.tty.In, a.tty.Out, nil, a.tty.Raw, terminalSizeQueue)
	}
}

type defaultRemoteExec struct{}

func (*defaultRemoteExec) Exec(method string, url *url.URL, config *restclient.Config, stdin io.Reader, stdout, stderr io.Writer, tty bool, terminalSizeQueue remotecommand.TerminalSizeQueue) error {
	exec, err := remotecommand.NewSPDYExecutor(config, method, url)
	if err != nil {
		return err
	}
	return exec.Stream(remotecommand.StreamOptions{
		Stdin:             stdin,
		Stdout:            stdout,
		Stderr:            stderr,
		Tty:               tty,
		TerminalSizeQueue: terminalSizeQueue,
	})
}

func setupTTY(out io.Writer, in io.Reader) (term.TTY, error) {
	t := term.TTY{
		Out: out,
		In:  in,
		Raw: true,
	}

	if !t.IsTerminalIn() {
		return t, fmt.Errorf("unable to use a TTY if the input is not a terminal")
	}

	return t, nil
}
