---
title: Releasing
weight: 100
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

2. Tag a release canditate version

```bash
$ git tag v0.x.0-rc
```

3. Push tag to remote

```bash
$ git push origin v0.x.0-rc
```

4. Verify that the CI for the tag passed

5. Tag the real release

```bash
$ git push origin v0.x.0
```

6. Push tag for real release

```bash
$ git push origin v0.x.0
```

7. Once the CI is done, go to https://github.com/inspektor-gadget/inspektor-gadget/releases and edit
   the created release. Then click `Generate release notes` and update them to match the format used
   for other releases:

```
< Relevant changes >

### General Improvements
### Bug Fixes
### Documentation Improvements
### Testing and Continue Integration
```

8. Verify that the CI created a pull request in
   [krew-index](https://github.com/kubernetes-sigs/krew-index/pulls) and that it was merged
   automatically be the bot

9. Send an announcement on the [#inspektor-gadget](https://kubernetes.slack.com/archives/CSYL75LF6) Slack channel

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
