// Copyright The OpenTelemetry Authors
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

// Source
// https://github.com/grafana/beyla/blob/main/bpf/headers/utils.h

#ifndef __UTILS_H__
#define __UTILS_H__

#if defined(__TARGET_ARCH_x86)

#define GO_PARAM1(x) ((void*)(x)->ax)
#define GO_PARAM2(x) ((void*)(x)->bx)
#define GO_PARAM3(x) ((void*)(x)->cx)
#define GO_PARAM4(x) ((void*)(x)->di)
#define GO_PARAM5(x) ((void*)(x)->si)
#define GO_PARAM6(x) ((void*)(x)->r8)
#define GO_PARAM7(x) ((void*)(x)->r9)
#define GO_PARAM8(x) ((void*)(x)->r10)
#define GO_PARAM9(x) ((void*)(x)->r11)

// In x86, current goroutine is pointed by r14, according to
// https://go.googlesource.com/go/+/refs/heads/dev.regabi/src/cmd/compile/internal-abi.md#amd64-architecture
#define GOROUTINE_PTR(x) ((void*)(x)->r14)

#elif defined(__TARGET_ARCH_arm64)

// Source
// https://github.com/grafana/beyla/blob/main/bpf/headers/bpf_tracing.h
/* arm64 provides struct user_pt_regs instead of struct pt_regs to userspace */
struct pt_regs;
#define PT_REGS_ARM64 const volatile struct user_pt_regs

#define GO_PARAM1(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[0])
#define GO_PARAM2(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[1])
#define GO_PARAM3(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[2])
#define GO_PARAM4(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[3])
#define GO_PARAM5(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[4])
#define GO_PARAM6(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[5])
#define GO_PARAM7(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[6])
#define GO_PARAM8(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[7])
#define GO_PARAM9(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[8])

// In arm64, current goroutine is pointed by R28 according to
// https://github.com/golang/go/blob/master/src/cmd/compile/abi-internal.md#arm64-architecture
#define GOROUTINE_PTR(x) ((void*)((PT_REGS_ARM64 *)(x))->regs[28])

#else 
#error Undefined architecture
#endif /*defined(__TARGET_ARCH_arm64)*/

#define bpf_clamp_umax(VAR, UMAX)                                                                  \
    asm volatile("if %0 <= %[max] goto +1\n"                                                       \
                 "%0 = %[max]\n"                                                                   \
                 : "+r"(VAR)                                                                       \
                 : [max] "i"(UMAX))
                 
#endif /* __UTILS_H__ */
