// Copyright 2025 The Inspektor Gadget authors
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

package containercollection

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type ecsCache struct {
	mu sync.RWMutex
	// runtimeContainerID (without runtime prefix) -> ecs metadata
	byRuntimeID map[string]EcsMetadata
}

func newEcsCache() *ecsCache {
	return &ecsCache{
		byRuntimeID: make(map[string]EcsMetadata),
	}
}

func (c *ecsCache) set(runtimeID string, md EcsMetadata) {
	if runtimeID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byRuntimeID[runtimeID] = md
}

func (c *ecsCache) get(runtimeID string) (EcsMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	md, ok := c.byRuntimeID[runtimeID]
	return md, ok
}

// withEcsEnrichment enables ECS metadata enrichment for containers.
//
// IMPORTANT: Fargate Limitation
// This enricher currently only works with EC2 launch type tasks. Fargate tasks
// do not expose a RuntimeId that can be matched against local container runtimes.
// On EC2, the ECS agent runs alongside containers and we can match the RuntimeId
// (e.g., "docker://abc123") to the local Docker/containerd container ID.
// On Fargate, there is no local container runtime to hook into since tasks run
// in AWS-managed infrastructure.
//
// Future work: Fargate support would require a different approach, such as:
// - Running as a sidecar container within the Fargate task
// - Using the ECS Task Metadata Endpoint (available inside the task)
// - Matching by other identifiers like PID namespace or cgroup paths
func withEcsEnrichment(cc *ContainerCollection, clusterName, region string) error {
	if clusterName == "" {
		return fmt.Errorf("ecs enricher: clusterName is required")
	}
	if region == "" {
		return fmt.Errorf("ecs enricher: region is required")
	}

	cache := newEcsCache()

	// Enrich on AddContainer using the latest cache snapshot (mirrors the K8s enricher model).
	cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
		// Skip if already enriched
		if container.Ecs.BasicEcsMetadata.IsEnriched() {
			return true
		}

		// ContainerID in IG is already "without runtime prefix" (per types.BasicRuntimeMetadata docs),
		// so it should match ECS RuntimeId after stripping docker://, containerd://, etc.
		runtimeID := container.Runtime.ContainerID
		if runtimeID == "" {
			return true
		}

		md, ok := cache.get(runtimeID)
		if !ok {
			return true
		}

		container.Ecs = md
		return true
	})

	// Discovery loop: keep cache updated from ECS API.
	// This lives in container-collection (like WithKubernetesEnrichment).
	go ecsDiscoveryLoop(cc, clusterName, region, cache)

	log.Infof("ecs enricher enabled (cluster=%s region=%s)", clusterName, region)
	return nil
}

func ecsDiscoveryLoop(cc *ContainerCollection, clusterName, region string, cache *ecsCache) {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Errorf("ecs enricher: loading AWS config: %v", err)
		return
	}
	client := ecs.NewFromConfig(cfg)

	// simple periodic refresh; we'll optimize later with delta logic in the operator layer
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// do an initial refresh quickly
	refreshEcsCache(ctx, client, clusterName, cache)
	updateExistingContainersWithEcs(cc, cache)

	for {
		select {
		case <-cc.done:
			return
		case <-ticker.C:
			refreshEcsCache(ctx, client, clusterName, cache)
			updateExistingContainersWithEcs(cc, cache)
		}
	}
}

// updateExistingContainersWithEcs enriches any containers in the collection
// that don't have ECS metadata yet but can now be matched from the cache.
func updateExistingContainersWithEcs(cc *ContainerCollection, cache *ecsCache) {
	cc.containers.Range(func(key, value any) bool {
		container := value.(*Container)
		if container.Ecs.BasicEcsMetadata.IsEnriched() {
			return true
		}
		runtimeID := container.Runtime.ContainerID
		if runtimeID == "" {
			return true
		}
		if md, ok := cache.get(runtimeID); ok {
			container.Ecs = md
			log.Debugf("ecs enricher: enriched existing container %s with ECS metadata", runtimeID)
		}
		return true
	})
}

func refreshEcsCache(ctx context.Context, client *ecs.Client, clusterName string, cache *ecsCache) {
	taskArns, err := listAllTasks(ctx, client, clusterName)
	if err != nil {
		log.Errorf("ecs enricher: list tasks: %v", err)
		return
	}

	tasks, err := describeTasksBatched(ctx, client, clusterName, taskArns)
	if err != nil {
		log.Errorf("ecs enricher: describe tasks: %v", err)
		return
	}

	for _, task := range tasks {
		clusterArn := aws.ToString(task.ClusterArn)
		taskArn := aws.ToString(task.TaskArn)
		taskDefArn := aws.ToString(task.TaskDefinitionArn)
		launchType := string(task.LaunchType)
		az := ""
		if task.AvailabilityZone != nil {
			az = *task.AvailabilityZone
		}

		serviceName := parseServiceNameFromGroup(aws.ToString(task.Group))

		// task family/revision parsing best-effort from task definition arn
		taskFamily, taskRevision := parseTaskFamilyRevision(taskDefArn)

		for _, c := range task.Containers {
			runtimeID := normalizeRuntimeID(aws.ToString(c.RuntimeId))
			containerName := aws.ToString(c.Name)

			md := EcsMetadata{
				BasicEcsMetadata: types.BasicEcsMetadata{
					ClusterName:   clusterName,
					TaskFamily:    taskFamily,
					TaskRevision:  taskRevision,
					ServiceName:   serviceName,
					ContainerName: containerName,
					LaunchType:    launchType,
				},
				ClusterARN:        clusterArn,
				TaskARN:           taskArn,
				TaskDefinitionARN: taskDefArn,
				ContainerARN:      aws.ToString(c.ContainerArn),
				AvailabilityZone:  az,
				ContainerInstance: aws.ToString(task.ContainerInstanceArn),
			}

			cache.set(runtimeID, md)
		}
	}
}

func listAllTasks(ctx context.Context, client *ecs.Client, clusterName string) ([]string, error) {
	var all []string
	var nextToken *string
	for {
		out, err := client.ListTasks(ctx, &ecs.ListTasksInput{
			Cluster:   aws.String(clusterName),
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, out.TaskArns...)
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return all, nil
}

func describeTasksBatched(ctx context.Context, client *ecs.Client, clusterName string, taskArns []string) ([]ecstypes.Task, error) {
	if len(taskArns) == 0 {
		return nil, nil
	}
	const max = 100
	var all []ecstypes.Task
	for i := 0; i < len(taskArns); i += max {
		end := i + max
		if end > len(taskArns) {
			end = len(taskArns)
		}
		out, err := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
			Cluster: aws.String(clusterName),
			Tasks:   taskArns[i:end],
		})
		if err != nil {
			return nil, err
		}
		all = append(all, out.Tasks...)
	}
	return all, nil
}

func normalizeRuntimeID(runtimeID string) string {
	// ECS returns RuntimeId like "docker://<id>" on EC2; strip any scheme/prefix.
	if runtimeID == "" {
		return ""
	}
	if strings.Contains(runtimeID, "://") {
		parts := strings.SplitN(runtimeID, "://", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return runtimeID
}

func parseServiceNameFromGroup(group string) string {
	// ECS task.Group commonly "service:<name>"
	if strings.HasPrefix(group, "service:") {
		return strings.TrimPrefix(group, "service:")
	}
	return group
}

func parseTaskFamilyRevision(taskDefArn string) (family, revision string) {
	// arn:aws:ecs:region:acct:task-definition/family:revision
	// best effort parse
	slash := strings.LastIndex(taskDefArn, "/")
	if slash == -1 || slash == len(taskDefArn)-1 {
		return "", ""
	}
	last := taskDefArn[slash+1:]
	colon := strings.LastIndex(last, ":")
	if colon == -1 {
		return last, ""
	}
	return last[:colon], last[colon+1:]
}
