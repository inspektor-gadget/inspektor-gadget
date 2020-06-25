# Contributing to Inspektor Gadget

## Contents

- [Architecture](#architecture)
- [Setup developer environment](#setup-developer-environment)
- [Building the code](#building-the-code)
  - [Building the client executable](#building-the-client-executable)
  - [Building the gadget container image](#building-the-gadget-container-image)
- [Workflows](#workflows)
  - [Github Actions](#github-actions)
  - [Minikube](#development-environment-on-minikube-for-the-traceloop-gadget)
- [Testing](#testing)
  - [Unit tests](#unit-tests)
  - [Integration tests](#integration-tests)
- [Authoring PRs](#authoring-prs)
- [Good first issues](#good-first-issues)
- [Proposing new features](#proposing-new-features)
- [Porting BCC gadgets](#porting-bcc-gadgets)

## Architecture

It's highly recommended to read the [architecture](./Documentation/architecture.md) documentation before starting
to play with Inspektor Gadget.

## Setup developer environment

- [Fork](https://github.com/kinvolk/inspektor-gadget/fork) and clone this repo.
    - `git clone git@github.com:your_account/inspektor-gadget.git`.
- Install [Docker](https://docs.docker.com/get-docker/), [Golang](https://golang.org/doc/install).

## Building the code

Inspektor Gadget is composed by a client executable and a container image.
A container repository is needed to push the image. The following commands
use the value of the `CONTAINER_REPO` env variable, it defaults to
`docker.io/kinvolk/gadget` if not defined.

### Building the client executable

You can compile for all supported platforms by running `make kubectl-gadget`
or build for a specific one with `make kubectl-gadget-linux-amd64` or `make kubectl-gadget-darwin-amd64`.

Note:
- The compilation uses `tools/image-tag` to choose the tag of the container
image to use according to the branch that you are compiling.
- The container repository is set with the `CONTAINER_REPO` env variable.
- You can push the container images to another registry and use the `--image`
argument when deploying to the Kuberentes cluster.
- If you wish to make changes to traceloop program, update
`gadget-container/gadget.Dockerfile` to pick your own image of traceloop.

See the [minikube](#Development-environment-on-minikube-for-the-traceloop-gadget)
section for a faster development cycle.

### Building the gadget container image

You can build and push the container gadget image by running the following commands:

```
$ cd gadget-container
$ make build
$ make push
```

The BPF code is built using a Docker container, so you don't have to worry
installing the compilers to build it.

## Workflows

### Github Actions

This repo uses Github actions as CI. It compiles and uploads the Inspektor Gadget
executable and gadget container image. It also runs unit and some integration tests.
A fork of this project should
enable them in the repo settings page and add the following
[secrets](https://help.github.com/en/actions/configuring-and-managing-workflows/creating-and-storing-encrypted-secrets#creating-encrypted-secrets-for-a-repository) to be able to use them:

- `CONTAINER_REPO`: The container repository to use. Example: docker.io/kinvolk/gadget
- `CONTAINER_REGISTRY_USERNAME` & `CONTAINER_REGISTRY_PASSWORD`: Authentication information for the the repo above.

### Development environment on minikube for the traceloop gadget

It's possible to make changes to traceloop and test them on minikube locally without pushing container images to any registry.

* Make sure the git repositories `traceloop` and `inspektor-gadget` are cloned in sibling directories
* Minikube with the Docker driver does not work for traceloop. You can use another driver, for example:
```
$ minikube start --driver=kvm2
```
* Install Inspektor Gadget on minikube as usual:
```
$ kubectl gadget deploy | kubectl apply -f -
```
* Make changes in the traceloop repository and compile with `make`
* Generate the new gadget image and deploy it to minikube:
```
$ make -C gadget-container/ minikube
```

Note that the minikube image only works with the traceloop gadget.

## Testing

### Unit tests

You can run the different unit tests with:

```
$ make test
```

### Integration tests

The integration tests use a Kubernetes cluster to deploy and test Inspektor Gadget.
Be sure that you have a valid kubeconfig and run:

```
$ export KUBECONFIG=... # not needed if valid config in $HOME/.kube/config
$ make integration-tests
```

## Authoring PRs

These are general guidelines for making PRs/commits easier to review:

 * Commits should be atomic and self-contained. Divide logically separate changes
   to separate commits. This principle is best explained in the the Linux Kernel
   [submitting patches][linux-sep-changes] guide.

 * Commit messages should explain the intention, _why_ something is done. This,
   too, is best explained in [this section][linux-desc-changes] from the Linux
   Kernel patch submission guide.

 * Commit titles (the first line in a commit) should be meaningful and describe
   _what_ the commit does.

 * Don't add code you will change in a later commit (it makes it pointless to
   review that commit), nor create a commit to add code an earlier commit should
   have added. Consider squashing the relevant commits instead.

 * It's not important to retain your development history when contributing a
   change. Use `git rebase` to squash and order commits in a way that makes them easy to
   review. Keep the final, well-structured commits and not your development history
   that led to the final state.

 * Consider reviewing the changes yourself before opening a PR. It is likely
   you will catch errors when looking at your code critically and thus save the
   reviewers (and yourself) time.

 * Use the PR's description as a "cover letter" and give the context you think
   reviewers might need. Use the PR's description to explain why you are
   proposing the change, give an overview, raise questions about yet-unresolved
   issues in your PR, list TODO items etc.

PRs which follow these rules are easier to review and merge.

[linux-sep-changes]: https://www.kernel.org/doc/html/v4.17/process/submitting-patches.html#separate-your-changes
[linux-desc-changes]: https://www.kernel.org/doc/html/v4.17/process/submitting-patches.html#describe-your-changes

## Good first issues

If you're looking where to start, you can check the issues with the
`good first issue` label on
[Inspektor Gadget](https://github.com/kinvolk/inspektor-gadget/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) or
[traceloop](https://github.com/kinvolk/traceloop/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22).
Don't hesitate to
[talk with us](https://github.com/kinvolk/inspektor-gadget#discussions)
if you need further help.

## Proposing new features

If you want to propose a new feature or do a big change in the architecture
it's highly recommended to open an issue first to discuss it with the team.

## Porting BCC gadgets

This project uses some gadgets from [BCC](https://github.com/iovisor/bcc/).
Instead of keeping our patched versions, we prefer to make those gadgets
suitable to be used with Inspektor Gadget by contributing to the upstream project.

A BCC gadget has to provide a
[filtering mechanism](https://github.com/iovisor/bcc/blob/master/docs/special_filtering.md)
by cgroup id and mount namespace id in order to be compatible with Inspektor Gadget.
You can get some inspiration from the
[opensnoop](https://github.com/iovisor/bcc/blob/8cd2717de91983aeeadefd0886031bd4d8e920ee/tools/opensnoop.py#L127) and
[execsnoop](https://github.com/iovisor/bcc/blob/8cd2717de91983aeeadefd0886031bd4d8e920ee/tools/execsnoop.py#L149)
implementations to port a different BCC gadget.

Once the gadget has been updated in the BCC repo, it can be added to Inspektor
Gadget by filling a PR adding the gadget to
[`cmd/kubectl-gadget/bcck8s.go`](https://github.com/kinvolk/inspektor-gadget/blob/0cf97d9ea6432f080eafa1a3280f3447085ea96a/cmd/kubectl-gadget/bcck8s.go#L26).
The [add gadget bindsnoop](https://github.com/kinvolk/inspektor-gadget/pull/35/files#diff-f616fa5f11da59a9ae7344d196bbf357R40-R43)
PR is an example of it.

The [adding new BCC-based gadgets in Inspektor Gadget](https://kinvolk.io/blog/2020/04/adding-new-bcc-based-gadgets-in-inspektor-gadget/)
blogpost presents some more details about this process.
