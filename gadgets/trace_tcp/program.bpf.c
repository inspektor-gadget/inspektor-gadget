// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#include "ebpf/connect.bpf.c"
#include "ebpf/tcp.bpf.c"

char LICENSE[] SEC("license") = "GPL";
