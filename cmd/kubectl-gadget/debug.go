// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
)

func getGadgetPodsDebug(client *kubernetes.Clientset) string {
	var sb strings.Builder

	listOpts := metav1.ListOptions{
		LabelSelector: "k8s-app=" + utils.GadgetNamespace,
	}

	pods, err := client.CoreV1().Pods(utils.GadgetNamespace).List(context.TODO(), listOpts)
	if err != nil {
		return ""
	}

	for _, pod := range pods.Items {
		pod.ManagedFields = nil
		bytes, err := yaml.Marshal(pod)
		if err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("------ Pod %s -------\n", pod.Name))
		sb.Write(bytes)
		sb.WriteString("---------------------\n")

		sb.WriteString(fmt.Sprintf("----------------- LOGS START (%s) -----------------\n", pod.Name))
		sb.WriteString(getPodLog(client, pod.Name))
		sb.WriteString("------------------ LOGS END ------------------\n")
	}

	return sb.String()
}

func getPodLog(client *kubernetes.Clientset, podname string) string {
	podLogOpts := corev1.PodLogOptions{}
	req := client.CoreV1().Pods(utils.GadgetNamespace).GetLogs(podname, &podLogOpts)
	if req == nil {
		return ""
	}

	stream, err := req.Stream(context.TODO())
	if err != nil {
		return ""
	}
	defer stream.Close()

	buf := new(strings.Builder)
	_, err = io.Copy(buf, stream)
	if err != nil {
		return ""
	}

	return buf.String()
}

// taken from https://github.com/kubernetes/kubectl/blob/393c40f5c4acbe48edbc70f8c8696bb623744b76/pkg/cmd/events/events.go#L362-L372
// Return the time that should be used for sorting, which can come from
// various places in corev1.Event.
func eventTime(event corev1.Event) time.Time {
	if event.Series != nil {
		return event.Series.LastObservedTime.Time
	}
	if !event.LastTimestamp.Time.IsZero() {
		return event.LastTimestamp.Time
	}
	return event.EventTime.Time
}

func getEvents(client *kubernetes.Clientset) string {
	var sb strings.Builder

	events, err := client.CoreV1().Events(utils.GadgetNamespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return ""
	}

	sb.WriteString(fmt.Sprintf("%-12s %-10s %-14s %-30s %s\n",
		"LAST SEEN", "TYPE", "REASON", "OBJECT", "MESSAGE"))

	now := time.Now()

	for _, event := range events.Items {
		dur := now.Sub(eventTime(event)).Truncate(time.Second)
		sb.WriteString(fmt.Sprintf("%-12s %-10s %-14s %-30s %s\n",
			dur, event.Type, event.Reason,
			event.InvolvedObject.Kind+"\\"+event.InvolvedObject.Name, event.Message))
	}

	return sb.String()
}
