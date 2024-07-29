---
title: Releasing
sidebar_position: 220
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

- Create a branch for this release named `release-v0.x`, this will be used as stable branch where fixes would be backported:

```bash
$ git checkout -b release-v0.x
$ git push --set-upstream origin release-v0.x
```

- Check if the [milestone for the release](https://github.com/inspektor-gadget/inspektor-gadget/milestones) still
  contain open issues. If so, move them as appropriate. Close the milestone.

- Check the automatic pull request updating the [Inspektor Gadget website](https://inspektor-gadget.io/) and merge as appropriate ([example for v0.22.0](https://github.com/inspektor-gadget/website/pull/27)).

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

## Making a bugfix release

All newly merged patches fixing previous bug have to be backported to the latest release.
When you merge a PR containing a patch fixing a bug, you should test if the buggy commits belongs to the latest release.
Let's take an example with this commit:

```patch
commit 95fe7405738d58476ddad29856ebe30599644666
Author: author <author@mail.com>
Date:   Tue Jan 9 16:42:38 2024 +0100

    check for empty record in capabilities tracer to avoid a panic

    Fixes: 39aefb92dd1df2ff73647b17707984662f8718c0 ("pkg/gadgets: Add capabilities CO-RE tracer.")
    Signed-off-by: author <author@mail.com>
```

To test if the buggy commit belongs to the latest release, you can use the following:

```bash
$ git tag --contains 39aefb92dd1df2ff73647b17707984662f8718c0 --sort=-v:refname
v0.x.y
...
v0.x.1
v0.x.0
v0.24.0
v0.23.1
```

You now need to backport the patch to the latest release branch:

```bash
$ git checkout release-v0.x
$ git pull
$ git checkout -b release-v0.x/fix-something
$ git cherry-pick 95fe7405738d58476ddad29856ebe30599644666
# If the patch does not apply cleanly, you will need to adapt it.
# Once done, push your branch and open a PR against the release branch:
$ git push --set-upstream origin release-v0.x/fix-something
```

Even if the patch applies cleanly, you need to open a PR.
Once your PR is merged, you can now create the bugfix tag:

```bash
$ git checkout release-v0.x
$ git pull
# Where z would be y + 1:
$ git tag v0.x.z
```

Once done, follow the instructions listed [here](#making-a-new-release), to create a new release.
