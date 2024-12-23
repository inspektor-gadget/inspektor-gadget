// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation
//
// Based on tcptracer(8) from BCC by Kinvolk GmbH and
// tcpconnect(8) by Anton Protopopov

#include "ebpf/connect.h"
#include "ebpf/tcp.h"

char LICENSE[] SEC("license") = "GPL";
