---
title: About Continuous Integration
weight: 20
description: >
  Inspektor Gadget continuous integration workflow
---

This repository uses GitHub Actions to create a custom Continuous Integration
(CI) workflow named `Inspektor Gadget CI`. This workflow compiles and uploads
the Inspektor Gadget CLI, local-gadget and gadget container image and runs their
unit and integration tests. In addition, it verifies that the documentation is
up-to-date and runs a static code analysis using Golang linters.

A fork of this project should enable GitHub Actions in the repo settings page
and add the proper
[secrets](https://help.github.com/en/actions/configuring-and-managing-workflows/creating-and-storing-encrypted-secrets#creating-encrypted-secrets-for-a-repository)
to be able to use this workflow. The following sections describes what
secrets needs to be added to enable all the CI tests.

## Container repository

To run the integration tests, it is necessary to have the gadget container image
available on a container repository so that it can be installed in the
Kubernetes cluster where the tests will run.

As a default, `ghcr.io/${{ github.repository }}-dev` is used to store images
created in the CI pipeline for all branches except main and tags.
When the target branch correspond to the main or the push refers to a tag, the
default repository is `ghcr.io/${{ github.repository }}`.
This permits a clear separation between "in development" images and production
ones.
During a release, integration test container image will be pushed to
`ghcr.io/${{ github.repository }}-test`.

Note that, you need to [set repository packages as public](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility#configuring-visibility-of-container-images-for-your-personal-account) to allow anonymous pull.

## Run integration tests on an ARO cluster

Optionally, we can add the secrets described in this section so that the
integration tests will also run on a pre-created [Azure Red Hat OpenShift
(ARO)](https://docs.microsoft.com/en-us/azure/openshift/intro-openshift)
cluster. Consider that the Inspektor Gadget workflow will still success even if
no ARO cluster is provided through these secrets.

### Create a cluster

These are the steps to create an ARO cluster using the [Azure
CLI](https://docs.microsoft.com/en-us/cli/azure/):

```bash
$ export SUBSCRIPTION=<mySubscription>
$ export RESOURCEGROUP=<myResourceName>
$ export LOCATION=<myLocation>
$ export CLUSTER=<myCluster>
$ export VNET=<myVNET>
$ export MASTSUB=<myMASTSUB>
$ export WORKSUB=<myWORKSUB>

# Set subscription so that we don't need to specify it at every command
$ az account set --subscription $SUBSCRIPTION

# Register resource providers
$ az provider register -n Microsoft.RedHatOpenShift --wait
$ az provider register -n Microsoft.Compute --wait
$ az provider register -n Microsoft.Storage --wait
$ az provider register -n Microsoft.Authorization --wait

# Create resource group
$ az group create --name $RESOURCEGROUP --location $LOCATION

# Create virtual network and two empty subnets for the master and the worker nodes.
$ az network vnet create --resource-group $RESOURCEGROUP --name $VNET --address-prefixes 10.0.0.0/22
$ az network vnet subnet create --resource-group $RESOURCEGROUP --vnet-name $VNET --name $MASTSUB --address-prefixes 10.0.0.0/23 --service-endpoints Microsoft.ContainerRegistry
$ az network vnet subnet create --resource-group $RESOURCEGROUP --vnet-name $VNET --name $WORKSUB --address-prefixes 10.0.2.0/23 --service-endpoints Microsoft.ContainerRegistry
$ az network vnet subnet update --name $MASTSUB --resource-group $RESOURCEGROUP --vnet-name $VNET --disable-private-link-service-network-policies true

# Create the cluster (Minimum 3 worker nodes must be used)
$ az aro create --resource-group $RESOURCEGROUP --name $CLUSTER --vnet $VNET --master-subnet $MASTSUB --worker-count 3 --worker-subnet $WORKSUB
```

Considerations:
- After executing the `az aro create` command, it normally takes about 35
  minutes to create a cluster.
- For the sack of simplicity, we are not providing a [Red Hat pull
  secret](https://docs.microsoft.com/en-us/azure/openshift/tutorial-create-cluster#get-a-red-hat-pull-secret-optional)
  during the cluster creation, so our cluster will not include samples or
  operators from Red Hat or certified partners. However, it is not a requirement
  to run the Inspektor Gadget integration tests on it.
- Creating an ARO cluster requires specific permissions, check [the
  documentation](https://docs.microsoft.com/en-us/azure/openshift/tutorial-create-cluster#verify-your-permissions)
  to be sure you have them.

### Delete a cluster

If we need to delete our cluster, it is enough to execute:
```bash
$ az group delete --name $RESOURCEGROUP
```

Take into account that it will remove the entire resource group and all
resources inside it.

Further details about creating an ARO cluster can be found in the [Azure Red Hat
OpenShift
documentation](https://docs.microsoft.com/en-us/azure/openshift/tutorial-create-cluster).

### Connect to a cluster

Fist of all, to be able to connect to our cluster, we need the following
information:

```bash
# API Server URL
$ az aro show --subscription $SUBSCRIPTION -g $RESOURCEGROUP -n $CLUSTER --query apiserverProfile.url
https://api.server.example.io:1234

# Credentials
$ az aro list-credentials --subscription $SUBSCRIPTION -g $RESOURCEGROUP -n $CLUSTER
{
  "kubeadminPassword": "myPassword",
  "kubeadminUsername": "myUsername"
}
```

#### From GitHub actions

The `test-integration` job is already configured to authenticate and set the
kubeconf context to the ARO cluster configured in the GitHub repository. So all
we need to do is to add the following actions secrets:

- `OPENSHIFT_SERVER`: The API server URL: `https://api.server.example.io:1234`.
- `OPENSHIFT_USER`: The `kubeadminUsername` from the JSON output of the
  `list-credentials` command.
- `OPENSHIFT_PASSWORD`: The `kubeadminPassword` from the JSON output of the
  `list-credentials` command.

Further details about connect to an ARO cluster from GitHub actions can be found
in the [Azure Red Hat OpenShift
documentation](https://docs.microsoft.com/en-us/azure/openshift/tutorial-connect-cluster#connect-using-the-openshift-cli)
and the [redhat-actions/oc-login
documentation](https://github.com/redhat-actions/oc-login).

#### From a host

For debugging, it might be necessary to connect to the cluster from a host. We
can do it by using the `oc` tool:

```bash
$ oc login $apiServer -u $kubeadminUsername -p $kubeadminPassword
```

Notice that it configures the kubectl configuration with a new context.

Please take into account that any change done on this cluster could cause issues
with the integration tests running on GitHub actions at that moment.
