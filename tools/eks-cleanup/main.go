// Copyright 2024 The Inspektor Gadget authors
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

// This program is used to cleanup some resources that are leaked by the CI when running on EKS: See
// - https://github.com/inspektor-gadget/inspektor-gadget/issues/2533
// - https://github.com/eksctl-io/eksctl/issues/7589

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	region              = "us-east-2"
	igCiTagKey          = "ig-ci"
	igCiTimestampTagKey = "ig-ci-timestamp"
	stackNameTagKey     = "aws:cloudformation:stack-name"
	lifetime            = 3 * time.Hour
)

var dryRun = flag.Bool("dryrun", false, "don't remove anything")

func hasCloudFormationIgCiTag(tags []cftypes.Tag) bool {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == igCiTagKey {
			return true
		}
	}

	return false
}

func getCloudFormationIgCiTimestampTag(tags []cftypes.Tag) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == igCiTimestampTagKey {
			return aws.ToString(tag.Value)
		}
	}

	return ""
}

// getOldStacks returns all stacks created by the CI that are older than 3 hours
func getOldStacks(ctx context.Context, svc *cloudformation.Client) (map[string]cftypes.Stack, error) {
	result, err := svc.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{})
	if err != nil {
		return nil, fmt.Errorf("describing stacks: %w", err)
	}

	ret := map[string]cftypes.Stack{}
	for _, stack := range result.Stacks {
		// Only include stacks with the ig-ci tag
		if !hasCloudFormationIgCiTag(stack.Tags) {
			continue
		}

		timestamp := getCloudFormationIgCiTimestampTag(stack.Tags)
		if timestamp == "" {
			continue
		}

		// Only include stacks that are older than 3 hours
		createdAt, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {

			return nil, fmt.Errorf("parsing timestamp for stack %s: %v", aws.ToString(stack.StackName), err)
		}
		if createdAt.After(time.Now().Add(-1 * lifetime)) {
			fmt.Printf("skipping stack %s\n", aws.ToString(stack.StackName))
			continue
		}

		ret[aws.ToString(stack.StackName)] = stack
	}

	return ret, nil
}

func hasIgciTag(tags []ec2types.Tag) bool {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == igCiTagKey {
			return true
		}
	}

	return false
}

func getOldVpcs(ctx context.Context, svc *ec2.Client) (map[string]ec2types.Vpc, error) {
	input := &ec2.DescribeVpcsInput{}

	ret := map[string]ec2types.Vpc{}
	result, err := svc.DescribeVpcs(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("describing VPCs: %w", err)
	}

	for _, vpc := range result.Vpcs {
		if !hasIgciTag(vpc.Tags) {
			continue
		}

		tag := getTagValue(vpc.Tags, stackNameTagKey)
		// extra safe mechanism
		if tag == "" {
			continue
		}

		timestamp := getTagValue(vpc.Tags, igCiTimestampTagKey)
		if timestamp == "" {
			continue
		}

		// Only include stacks that are older than 3 hours
		createdAt, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {
			continue
		}
		if createdAt.After(time.Now().Add(-1 * lifetime)) {
			fmt.Printf("skipping VPC %s\n", aws.ToString(vpc.VpcId))
			continue
		}

		ret[aws.ToString(vpc.VpcId)] = vpc
	}

	return ret, nil
}

func getTagValue(tags []ec2types.Tag, key string) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == key {
			return aws.ToString(tag.Value)
		}
	}

	return ""
}

func detachAndDeleteInternetGateways(ctx context.Context, svc *ec2.Client, vpcId string) error {
	gateways, err := svc.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		return fmt.Errorf("describing internet gateways: %w", err)
	}
	for _, gateway := range gateways.InternetGateways {
		if !hasIgciTag(gateway.Tags) {
			continue
		}

		for _, attachment := range gateway.Attachments {
			if aws.ToString(attachment.VpcId) != vpcId {
				// not attached to this vpc
				return nil
			}
			fmt.Printf("detaching internet gateway: %s\n", aws.ToString(gateway.InternetGatewayId))
			input := &ec2.DetachInternetGatewayInput{
				InternetGatewayId: gateway.InternetGatewayId,
				VpcId:             aws.String(vpcId),
				DryRun:            dryRun,
			}
			if _, err := svc.DetachInternetGateway(ctx, input); err != nil {
				return fmt.Errorf("detaching internet gateway: %w", err)
			}
		}

		fmt.Printf("deleting internet gateway: %s\n", aws.ToString(gateway.InternetGatewayId))
		input := &ec2.DeleteInternetGatewayInput{
			InternetGatewayId: gateway.InternetGatewayId,
			DryRun:            dryRun,
		}
		if _, err := svc.DeleteInternetGateway(ctx, input); err != nil {
			return fmt.Errorf("deleting internet gateway: %w", err)
		}
	}

	return nil
}

func deleteNetworkInterfaces(ctx context.Context, svc *ec2.Client, subnetId *string) error {
	networkInterfaces, err := svc.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("subnet-id"),
				Values: []string{aws.ToString(subnetId)},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("describing network interfaces: %w", err)
	}

	for _, networkInterface := range networkInterfaces.NetworkInterfaces {
		fmt.Printf("deleting network interface: %s\n", aws.ToString(networkInterface.NetworkInterfaceId))
		input := &ec2.DeleteNetworkInterfaceInput{
			NetworkInterfaceId: networkInterface.NetworkInterfaceId,
			DryRun:             dryRun,
		}
		if _, err := svc.DeleteNetworkInterface(ctx, input); err != nil {
			return fmt.Errorf("deleting network interface: %w", err)
		}
	}

	return nil
}

func deleteSubnets(ctx context.Context, svc *ec2.Client, vpcId string) error {
	subnets, err := svc.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []string{vpcId},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("describing subnets: %w", err)
	}

	for _, subnet := range subnets.Subnets {
		if !hasIgciTag(subnet.Tags) {
			continue
		}

		if err := deleteNetworkInterfaces(ctx, svc, subnet.SubnetId); err != nil {
			return fmt.Errorf("deleting network interfaces: %w", err)
		}

		fmt.Printf("deleting subnet: %s\n", aws.ToString(subnet.SubnetId))
		input := &ec2.DeleteSubnetInput{
			SubnetId: subnet.SubnetId,
			DryRun:   dryRun,
		}
		if _, err = svc.DeleteSubnet(ctx, input); err != nil {
			return fmt.Errorf("deleting subnet: %w", err)
		}
	}

	return nil
}

func deleteSecurityGroups(ctx context.Context, svc *ec2.Client, vpcId string) error {
	securityGroups, err := svc.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []string{vpcId},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("describing security groups: %w", err)
	}

	for _, securityGroup := range securityGroups.SecurityGroups {
		// TODO: security groups don't have the ig-ci tag
		//if !hasIgciTag(securityGroup.Tags) {
		//	continue
		//}

		if aws.ToString(securityGroup.GroupName) == "default" {
			continue
		}

		fmt.Printf("deleting security group: %s\n", aws.ToString(securityGroup.GroupId))
		input := &ec2.DeleteSecurityGroupInput{
			GroupId: securityGroup.GroupId,
			DryRun:  dryRun,
		}
		if _, err := svc.DeleteSecurityGroup(ctx, input); err != nil {
			return fmt.Errorf("deleting security group: %w", err)
		}
	}

	return nil
}

func deleteVpc(ctx context.Context, svc *ec2.Client, vpcId string) error {
	if err := detachAndDeleteInternetGateways(ctx, svc, vpcId); err != nil {
		return fmt.Errorf("deleting internet gateway: %w", err)
	}

	if err := deleteSubnets(ctx, svc, vpcId); err != nil {
		return fmt.Errorf("deleting subnets: %w", err)
	}

	if err := deleteSecurityGroups(ctx, svc, vpcId); err != nil {
		return fmt.Errorf("deleting security groups: %w", err)
	}

	input := &ec2.DeleteVpcInput{
		VpcId:  aws.String(vpcId),
		DryRun: dryRun,
	}
	if _, err := svc.DeleteVpc(ctx, input); err != nil {
		return fmt.Errorf("deleting VPC: %w", err)
	}

	return nil
}

func do(ctx context.Context) error {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	ec2Svc := ec2.NewFromConfig(cfg)
	cloudformationSvc := cloudformation.NewFromConfig(cfg)

	stacks, err := getOldStacks(ctx, cloudformationSvc)
	if err != nil {
		return fmt.Errorf("describing stacks: %w", err)
	}

	// Start deleting stacks
	for name := range stacks {
		fmt.Printf("deleting stack: %s\n", name)
		if *dryRun {
			continue
		}

		input := &cloudformation.DeleteStackInput{
			StackName: aws.String(name),
		}
		if _, err := cloudformationSvc.DeleteStack(ctx, input); err != nil {
			return fmt.Errorf("deleting stack: %w", err)
		}
	}

	// Wait for the deletions to go through
	waiter := cloudformation.NewStackDeleteCompleteWaiter(cloudformationSvc)
	for name := range stacks {
		fmt.Printf("waiting for stack to be deleted: %s\n", name)

		if err := waiter.Wait(ctx, &cloudformation.DescribeStacksInput{
			StackName: aws.String(name),
		}, 10*time.Minute); err != nil {
			fmt.Printf("waiting for stack to be deleted: %v", err)
		}
	}

	vpcs, err := getOldVpcs(ctx, ec2Svc)
	if err != nil {
		return fmt.Errorf("describing VPCs: %w", err)
	}

	// Delete vpcs
	for _, vpc := range vpcs {
		fmt.Printf("deleting VPC: %s\n", aws.ToString(vpc.VpcId))
		if err := deleteVpc(ctx, ec2Svc, aws.ToString(vpc.VpcId)); err != nil {
			fmt.Printf("deleting VPC: %s", err)
		}
	}

	return nil
}

func main() {
	flag.Parse()

	ctx := context.Background()
	if err := do(ctx); err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
}
