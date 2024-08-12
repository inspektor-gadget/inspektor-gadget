---
title: 'btfgen'
sidebar_position: 800
description: 'Making a gadget more portable'
---

[btfgen][btfgen] enables running gadgets on system that don't provide BTF
information. The `ig image build` command generates a new layer on the gadget
image with the BTF information of the types used by the gadget for the most
common kernels available in [btfhub][btfhub], this information is then used when
running the gadget if the kernel doesn't have BTF enabled.

## Enabling btfgen

Given that generating the BTF information for a gadget takes a while, this
support is disabled by default.

The [btfhub-archive][btfhub-archive] repository needs to be present on the machine:

```bash
$ git clone --depth 1 https://github.com/aquasecurity/btfhub-archive/ $HOME/btfhub-archive/
```

Then, pass the `--btfgen` and the path of the btfhub-archive repository to the
build command:

```bash
$ sudo ig image build . --btfgen --btfhub-archive $HOME/btfhub-archive -t myimage
```

The resulting image will contain the BTF information and can be pushed, run or
tagged as any other gadget image.

[btfgen]: https://www.inspektor-gadget.io/blog/2022/03/btfgen-one-step-closer-to-truly-portable-ebpf-programs
[btfhub]: https://github.com/aquasecurity/btfhub
[btfhub-archive]: https://github.com/aquasecurity/btfhub-archive/
