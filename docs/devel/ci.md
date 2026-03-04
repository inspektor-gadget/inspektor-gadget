---
title: Continuous Integration
sidebar_position: 210
description: >
  Inspektor Gadget continuous integration workflow
---

This repository uses GitHub Actions to create a custom Continuous Integration
(CI) workflow named `Inspektor Gadget CI`. This workflow compiles and uploads
the Inspektor Gadget CLI (`kubectl-gadget` and `ig`) and gadget container
images and runs their unit and integration tests. In addition, it verifies
that the documentation is up-to-date and runs a static code analysis using
Golang linters.

A fork of this project should enable GitHub Actions in the repo settings page
and add the proper
[secrets](https://help.github.com/en/actions/configuring-and-managing-workflows/creating-and-storing-encrypted-secrets#creating-encrypted-secrets-for-a-repository)
to be able to use this workflow. The following sections describes what
secrets need to be added to enable all the CI tests.

## Container repository

To run the integration tests, it is necessary to have the gadget container image
available so that it can be installed/loaded in the Kubernetes cluster where the
tests will run.

As a default, images are shared via artifacts between workflow jobs
for all CI pipeline. When the target branch correspond to the main or
the push refers to a tag, the images are also pushed to
`ghcr.io/${{ github.repository }}`. This permits a clear separation
between "in development" images and production ones.

Note that, you need to [set repository packages as public](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility#configuring-visibility-of-container-images-for-your-personal-account) to allow anonymous pull.

## Run integration tests on ARO

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
$ export SP_NAME=<myServicePrincipalName>

# Set subscription so that we don't need to specify it at every command
$ az account set --subscription $SUBSCRIPTION

# Register resource providers
$ az provider register -n Microsoft.RedHatOpenShift --wait
$ az provider register -n Microsoft.Compute --wait
$ az provider register -n Microsoft.Storage --wait
$ az provider register -n Microsoft.Authorization --wait

# Create resource group
$ az group create --name $RESOURCEGROUP --location $LOCATION --tags DO-NOT-DELETE='Inspektor Gadget CI, contact hello@inspektor-gadget.io'

# Create virtual network and two empty subnets for the master and the worker nodes.
$ az network vnet create --resource-group $RESOURCEGROUP --name $VNET --address-prefixes 10.0.0.0/22
$ az network vnet subnet create --resource-group $RESOURCEGROUP --vnet-name $VNET \
  --name $MASTSUB --address-prefixes 10.0.0.0/23 --service-endpoints Microsoft.ContainerRegistry
$ az network vnet subnet create --resource-group $RESOURCEGROUP --vnet-name $VNET \
  --name $WORKSUB --address-prefixes 10.0.2.0/23 --service-endpoints Microsoft.ContainerRegistry
$ az network vnet subnet update --name $MASTSUB --resource-group $RESOURCEGROUP --vnet-name $VNET \
  --disable-private-link-service-network-policies true

# Create the service principal for the cluster
$ SP_CREDENTIALS=$(az ad sp create-for-rbac -n $SP_NAME --role contributor --scopes "/subscriptions/${SUBSCRIPTION}/resourceGroups/${RESOURCEGROUP}")

$ SP_APPID=$(echo $SP_CREDENTIALS | jq '.appId')
$ SP_PASSWORD=$(echo $SP_CREDENTIALS | jq '.password')

# Create the cluster (Minimum 3 worker nodes must be used)
$ az aro create --resource-group $RESOURCEGROUP --name $CLUSTER --vnet $VNET \
  --master-subnet $MASTSUB --worker-count 3 --worker-subnet $WORKSUB \
  --client-id $SP_APPID --client-secret $SP_PASSWORD
```

Considerations:
- After executing the `az aro create` command, it normally takes about 35
  minutes to create a cluster.
- For the sake of simplicity, we are not providing a [Red Hat pull
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


## Run integration tests on AKS

When secrets described in the below sections are set, the integration tests
will also run on
[AKS clusters](https://docs.microsoft.com/en-us/azure/aks/intro-kubernetes).

### Create the clusters

As Inspektor Gadget support both `amd64` and `arm64`, two clusters will be
created when the CI is triggered.
There are some requirements before creating the needed components in Azure:
1. You should have created an [environment](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments) in GitHub for your repository.
2. Your account should have the "[Application Developer](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#application-developer)" as Microsoft Entra role, you can check this with the following:

```bash
# First, get your user object ID.
$ your_oid=$(az ad signed-in-user show --query id -o tsv)
# Then, get the "Application Developer" role ID.
$ app_dev_role_id=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?\$filter=displayName%20eq%20'Application%20Developer'&\$select=id,displayName" --query 'value[0].id' -o tsv)
# If the response is different than this, you need to contact your administrator
# to ask for this role.
$ az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId%20eq%20'${your_oid}'%20and%20roleDefinitionId%20eq%20'${app_dev_role_id}'&\$select=id,principalId,roleDefinitionId" --query 'value' -o json
[
  {
    "id": "...",
    "principalId": "...", # Should contain $your_oid.
    "roleDefinitionId": "..." # Should contain $app_dev_role_id.
  }
]
```

You can now follow [these instructions](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure?tabs=azure-cli%2Clinux) to enable your CI to create these clusters:

```bash
$ subscription_id=<mySubscriptionID>
$ resourcegroup=<myResourceName>
$ location=<myLocation>
$ app_name=<myAppName>
# federated_name should not have spaces!
$ federated_name=<myFederatedCredentialName>
$ organization=<myGitHubOrganization>
$ repository=<myGitHubRepository>
$ environment=<myCIJobEnvironment>
$ service_management_reference=<myServiceManagementReference>

# Set subscription so that we don't need to specify it at every command.
$ az account set --subscription $subscription_id

# Create resource group.
# This is not needed to generate secrets but it is mandatory to creates AKS
# cluster in the CI.
$ az group create --name $resourcegroup --location $location

# Register an application for your CI.
$ az ad app create --display-name $app_name --service-management-reference $service_management_reference
{
# It should reply with a big JSON object.
}

# Let's get the ID of the created application
$ app_id=$(az ad app list --filter "displayName eq '$app_name'" --query '[0].id' -o tsv)

# Let's create a service principal for the corresponding application.
$ az ad sp create --id $app_id
{
# It should reply with a big JSON object.
}

# We now want to get the service principal ID.
$ sp_id=$(az ad sp list --filter "displayName eq '$app_name'" --query '[0].id' -o tsv)

# Let's create a new role for this service principal.
$ az role assignment create --role contributor --assignee-object-id $sp_id --assignee-principal-type ServicePrincipal --scope /subscriptions/$subscription_id/resourceGroups/$resourcegroup
{
# It should reply with a big JSON object.
}

# Create the federated credential to be able to "az login" from the CI.
$ az ad app federated-credential create --id $app_id --parameters <(echo "{
  \"name\": \"${federated_name}\",
  \"issuer\": \"https://token.actions.githubusercontent.com\",
  \"subject\": \"repo:${organization}/${repository}:environment:${environment}\",
  \"description\": \"AKS federated credentials for CI\",
  \"audiences\": [
    \"api://AzureADTokenExchange\"
  ]
}")
{
# It replies with a JSON object which has name set to $federated_name.
}
```

After doing this, you will need to create several secrets:

1. `AZURE_AKS_CLIENT_ID`: The application ID as given by `az ad app list --display-name $app_name --query [0].appId`.
1. `AZURE_AKS_TENANT_ID`: The tenant ID as given by `az account show --query tenantId`.
1. `AZURE_AKS_SUBSCRIPTION_ID`: The subscription used to create the federated
credentials as given by `az account show --query id`.
1. `AZURE_AKS_RESOURCE_GROUP`: It stores the name of the resource group where
the clusters will be created.

The workflow will create the `amd64` and `arm64` clusters for you by using the
above information.
By default, each of this cluster features
[3 nodes](https://learn.microsoft.com/en-us/cli/azure/aks?view=azure-cli-latest#az-aks-create).
Once created, the integration tests will be run on these clusters.
Finally, the clusters are deleted, whatsoever is the result of the tests.

## Run integration tests on EKS

We use OpenID Connect to authenticate GitHub Actions against AWS. If you want to run the integration
tests on your fork, follow
[this](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
to configure your AWS account.

You need to create a role with the [minimum IAM
policies](https://eksctl.io/usage/minimum-iam-policies/) needed by eksctl. Save the name of this
role (including the rull `arn:aws..` prefix). in a [repository
variable](https://docs.github.com/en/actions/learn-github-actions/variables#creating-configuration-variables-for-a-repository)
named `AWS_ROLE`.

## Run integration tests on GKE

In order to run the integration tests on GKE on a fork, you need to set the following secrets:

- `GKE_PROJECT`: The GCP project where the GKE cluster is located.
- `GKE_SERVICE_ACCOUNT`: The service account used to authenticate to GCP.
- `GKE_WORKLOAD_IDENTITY_PROVIDER`: The workload identity provider used to authenticate to GCP.

these secrets use OpenID Connect to authenticate GitHub Actions against GCP for more information on how it works
you can check the GitHub documentation [here](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform#adding-a-google-cloud-workload-identity-provider).
The steps to create a service account and a workload identity provider can be found in the [google-github-actions/auth](https://github.com/google-github-actions/auth?tab=readme-ov-file#workload-identity-federation-through-a-service-account) repository till step 6.
In terms of permissions, the service account needs to have the following roles:

- `roles/container.admin`
- `roles/container.clusterAdmin`
- `roles/iam.serviceAccountUser`

You can see the guide [here](https://cloud.google.com/kubernetes-engine/docs/how-to/iam#assigning_roles_to_service_accounts) to see how these roles can be assigned to the service account.

## Benchmarks

Inspektor Gadget has benchmark tests that are automatically executed and
published by
[github-action-benchmark](https://github.com/benchmark-action/github-action-benchmark).
You can see the results on:

https://inspektor-gadget.github.io/ig-benchmarks/dev/bench/index.html

This requires a GitHub API token (secret `BENCHMARKS_TOKEN`) configured with read and write access to two repositories:
- [inspektor-gadget/inspektor-gadget](https://github.com/inspektor-gadget/inspektor-gadget): required to allow the bot to post comments
- [inspektor-gadget/ig-benchmarks](https://github.com/inspektor-gadget/ig-benchmarks/tree/gh-pages), see the `gh-pages` branch.

The GitHub Action is disabled for pushes on forks or PR from forks, so the result page will not be updated by forks.
In this way, forks can still use other parts of the CI without failing, even without the `BENCHMARKS_TOKEN` secret.

## Sign release artifact

We compute hash sum of all our release artifacts and the file containing these checksums is signed using [`cosign`](https://github.com/sigstore/cosign).
To sign this file, you will need to create a private key with an associated password:

```bash
$ cosign generate-key-pair
Enter password for private key:
Enter password for private key again:
Private key written to cosign.key
Public key written to cosign.pub
```

You will then need to store the content of `cosign.key` in the `COSIGN_PRIVATE_KEY` and the password you used to create the key in `COSIGN_PASSWORD`.
Without these secrets, the release job will not be run.
