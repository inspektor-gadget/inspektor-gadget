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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ec2"
)

const (
	region              = "us-east-2"
	igCiTagKey          = "ig-ci"
	igCiTimestampTagKey = "ig-ci-timestamp"
	stackNameTagKey     = "aws:cloudformation:stack-name"
	lifetime            = 3 * time.Hour
)

var dryRun = flag.Bool("dryrun", false, "don't remove anything")

func hasCloudFormationIgCiTag(tags []*cloudformation.Tag) bool {
	for _, tag := range tags {
		if aws.StringValue(tag.Key) == igCiTagKey {
			return true
		}
	}

	return false
}

func getCloudFormationIgCiTimestampTag(tags []*cloudformation.Tag) string {
	for _, tag := range tags {
		if aws.StringValue(tag.Key) == igCiTimestampTagKey {
			return aws.StringValue(tag.Value)
		}
	}

	return ""
}

// getOldStacks returns all stacks created by the CI that are older than 3 hours
func getOldStacks(svc *cloudformation.CloudFormation) (map[string]*cloudformation.Stack, error) {
	result, err := svc.DescribeStacks(&cloudformation.DescribeStacksInput{})
	if err != nil {
		return nil, fmt.Errorf("describing stacks: %w", err)
	}

	ret := map[string]*cloudformation.Stack{}
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

			return nil, fmt.Errorf("parsing timestamp for stack %s: %v", aws.StringValue(stack.StackName), err)
		}
		if createdAt.After(time.Now().Add(-1 * lifetime)) {
			fmt.Printf("skipping stack %s\n", aws.StringValue(stack.StackName))
			continue
		}

		ret[aws.StringValue(stack.StackName)] = stack
	}

	return ret, nil
}

func hasIgciTag(tags []*ec2.Tag) bool {
	for _, tag := range tags {
		if aws.StringValue(tag.Key) == igCiTagKey {
			return true
		}
	}

	return false
}

func getOldVpcs(svc *ec2.EC2) (map[string]*ec2.Vpc, error) {
	input := &ec2.DescribeVpcsInput{}

	ret := map[string]*ec2.Vpc{}
	result, err := svc.DescribeVpcs(input)
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
			fmt.Printf("skipping VPC %s\n", aws.StringValue(vpc.VpcId))
			continue
		}

		ret[aws.StringValue(vpc.VpcId)] = vpc
	}

	return ret, nil
}

func getTagValue(tags []*ec2.Tag, key string) string {
	for _, tag := range tags {
		if aws.StringValue(tag.Key) == key {
			return aws.StringValue(tag.Value)
		}
	}

	return ""
}

func detachAndDeleteInternetGateways(svc *ec2.EC2, vpcId string) error {
	gateways, err := svc.DescribeInternetGateways(&ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		return fmt.Errorf("describing internet gateways: %w", err)
	}
	for _, gateway := range gateways.InternetGateways {
		if !hasIgciTag(gateway.Tags) {
			continue
		}

		for _, attachment := range gateway.Attachments {
			if aws.StringValue(attachment.VpcId) != vpcId {
				// not attached to this vpc
				return nil
			}
			fmt.Printf("detaching internet gateway: %s\n", aws.StringValue(gateway.InternetGatewayId))
			input := &ec2.DetachInternetGatewayInput{
				InternetGatewayId: gateway.InternetGatewayId,
				VpcId:             aws.String(vpcId),
				DryRun:            dryRun,
			}
			if _, err := svc.DetachInternetGateway(input); err != nil {
				return fmt.Errorf("detaching internet gateway: %w", err)
			}
		}

		fmt.Printf("deleting internet gateway: %s\n", aws.StringValue(gateway.InternetGatewayId))
		input := &ec2.DeleteInternetGatewayInput{
			InternetGatewayId: gateway.InternetGatewayId,
			DryRun:            dryRun,
		}
		if _, err := svc.DeleteInternetGateway(input); err != nil {
			return fmt.Errorf("deleting internet gateway: %w", err)
		}
	}

	return nil
}

func deleteNetworkInterfaces(svc *ec2.EC2, subnetId *string) error {
	networkInterfaces, err := svc.DescribeNetworkInterfaces(&ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("subnet-id"),
				Values: []*string{subnetId},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("describing network interfaces: %w", err)
	}

	for _, networkInterface := range networkInterfaces.NetworkInterfaces {
		fmt.Printf("deleting network interface: %s\n", aws.StringValue(networkInterface.NetworkInterfaceId))
		input := &ec2.DeleteNetworkInterfaceInput{
			NetworkInterfaceId: networkInterface.NetworkInterfaceId,
			DryRun:             dryRun,
		}
		if _, err := svc.DeleteNetworkInterface(input); err != nil {
			return fmt.Errorf("deleting network interface: %w", err)
		}
	}

	return nil
}

func deleteSubnets(svc *ec2.EC2, vpcId string) error {
	subnets, err := svc.DescribeSubnets(&ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(vpcId)},
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

		if err := deleteNetworkInterfaces(svc, subnet.SubnetId); err != nil {
			return fmt.Errorf("deleting network interfaces: %w", err)
		}

		fmt.Printf("deleting subnet: %s\n", aws.StringValue(subnet.SubnetId))
		input := &ec2.DeleteSubnetInput{
			SubnetId: subnet.SubnetId,
			DryRun:   dryRun,
		}
		if _, err = svc.DeleteSubnet(input); err != nil {
			return fmt.Errorf("deleting subnet: %w", err)
		}
	}

	return nil
}

func deleteSecurityGroups(svc *ec2.EC2, vpcId string) error {
	securityGroups, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(vpcId)},
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

		if aws.StringValue(securityGroup.GroupName) == "default" {
			continue
		}

		fmt.Printf("deleting security group: %s\n", aws.StringValue(securityGroup.GroupId))
		input := &ec2.DeleteSecurityGroupInput{
			GroupId: securityGroup.GroupId,
			DryRun:  dryRun,
		}
		if _, err := svc.DeleteSecurityGroup(input); err != nil {
			return fmt.Errorf("deleting security group: %w", err)
		}
	}

	return nil
}

func deleteVpc(svc *ec2.EC2, vpcId string) error {
	if err := detachAndDeleteInternetGateways(svc, vpcId); err != nil {
		return fmt.Errorf("deleting internet gateway: %w", err)
	}

	if err := deleteSubnets(svc, vpcId); err != nil {
		return fmt.Errorf("deleting subnets: %w", err)
	}

	if err := deleteSecurityGroups(svc, vpcId); err != nil {
		return fmt.Errorf("deleting security groups: %w", err)
	}

	input := &ec2.DeleteVpcInput{
		VpcId:  aws.String(vpcId),
		DryRun: dryRun,
	}
	if _, err := svc.DeleteVpc(input); err != nil {
		return fmt.Errorf("deleting VPC: %w", err)
	}

	return nil
}

func do() error {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            aws.Config{Region: aws.String(region)},
	}))

	ec2Svc := ec2.New(sess)
	cloudformationSvc := cloudformation.New(sess)

	stacks, err := getOldStacks(cloudformationSvc)
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
		if _, err := cloudformationSvc.DeleteStack(input); err != nil {
			return fmt.Errorf("deleting stack: %w", err)
		}
	}

	// Wait for the deletions to go through
	for name := range stacks {
		fmt.Printf("waiting for stack to be deleted: %s\n", name)

		context, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		if err := cloudformationSvc.WaitUntilStackDeleteCompleteWithContext(context,
			&cloudformation.DescribeStacksInput{
				StackName: aws.String(name),
			}); err != nil {
			cancel()
			return fmt.Errorf("waiting for stack to be deleted: %w", err)
		}
		cancel()
	}

	vpcs, err := getOldVpcs(ec2Svc)
	if err != nil {
		return fmt.Errorf("describing VPCs: %w", err)
	}

	// Delete vpcs
	for _, vpc := range vpcs {
		fmt.Printf("deleting VPC: %s\n", aws.StringValue(vpc.VpcId))
		if err := deleteVpc(ec2Svc, aws.StringValue(vpc.VpcId)); err != nil {
			return fmt.Errorf("deleting VPC: %w", err)
		}
	}

	return nil
}

func main() {
	flag.Parse()

	if err := do(); err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
}
