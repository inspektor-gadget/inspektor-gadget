---
title: Releasing
weight: 220
description: >
  How to release Inspektor Gadget
---

The Inspektor Gadget release process is heavily automated, however some manual steps are still
required. This guide describes the process to make a new release of Inspektor Gadget and includes
some information of what to do in case something goes wrong.

Be sure you have a general understanding of the whole release process before starting to follow the
steps described here. It's also important to stay aware as a mistake could cause issues for our
users.

## Making a new release

0. Be sure tests on main branch are passing, please fix them if not.
1. Switch to the main branch and pull latest changes

```bash
$ git checkout main
$ git pull origin
```

Double check that the latest commit is the right one to make the release.

2. Tag the new version.

```bash
$ git tag v0.x.0
```

3. Push tag to remote

```bash
$ git push origin v0.x.0
```

4. Verify that the CI for the tag passed

5. Once the CI is done, go to https://github.com/inspektor-gadget/inspektor-gadget/releases and edit
   the created draft release. Then click `Generate release notes` and update them to match the format used
   for other releases:

```
< Relevant changes >

### General Improvements
### Bug Fixes
### Documentation Improvements
### Testing and Continue Integration
```

6. Once satisfied with the release notes, publish the draft release as public release.

7. Verify that the CI created a pull request in
   [krew-index](https://github.com/kubernetes-sigs/krew-index/pulls) and that it was merged
   automatically by the bot

8. Send an announcement on the [#inspektor-gadget](https://kubernetes.slack.com/archives/CSYL75LF6) Slack channel

## Post release tasks

- Check if the [milestone for the release](https://github.com/inspektor-gadget/inspektor-gadget/milestones) still
  contain open issues. If so, move them as appropriate. Close the milestone.

- Update the [Inspektor Gadget website](https://inspektor-gadget.io/) ([example for v0.16.0](https://github.com/inspektor-gadget/website/pull/14)).

- Update other projects using Inspektor Gadget:

  - Update the [Azure Kubernetes Service (AKS) Extension for Visual Studio Code](https://github.com/Azure/vscode-aks-tools/pull/191).

## Troubleshooting a failed release

### The CI process for the tag failed

It can happen that the CI fails because of a flaky test, it's fine to rerun the failed jobs to make
them pass.

### The krew-index PR wasn't merged automatically

In some situations the PR is not merged by the bot, in that case it's necessary to ping the
Krew maintainers to manually merge it.


## Release cadence

We try to make a new release the first Monday of each month, however we can delay it a bit if there
are issues that need to be handled before.

If there is a security issue or an important bug fix we make patch releases in between. We don't
have a formal definition of what an "important bug fix" is, it's up the team to discuss and decide
whether to make a new release or not.
