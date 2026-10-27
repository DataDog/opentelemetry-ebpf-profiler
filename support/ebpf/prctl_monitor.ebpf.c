// This file contains the code for the tracepoint on prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)
// to detect when a process names a memory mapping "OTEL_CTX".

#include "bpfdefs.h"
#include "tracemgmt.h"

#include "types.h"

// prctl constants from include/uapi/linux/prctl.h
#define PR_SET_VMA           0x53564d41
#define PR_SET_VMA_ANON_NAME 0

// Size of the OTEL_CTX header (OTEP 4719).
#define OTEL_CTX_HEADER_SIZE 32

// Signature of the OTEL_CTX header (OTEP 4719), as a u64.
#define OTEL_CTX_SIGNATURE (*(u64 *)"OTEL_CTX")

// tracepoint__sys_exit_prctl detects when a process names a mapping "OTEL_CTX",
// which publishers do to announce publications and updates of their process
// context. It records the header address in otel_ctx_events, so user space can
// re-read the context there without resynchronizing the process's mappings.
//
// The address is recorded whatever prctl returned: naming is unavailable
// before Linux 5.17 or without CONFIG_ANON_VMA_NAME, and fails for memfd-backed
// headers before Linux 6.2. If the hook can't read the name, the header's
// signature identifies the announcement instead. User space validates the
// header itself.
//
// We hook syscall exit, not entry: on the normal naming path, the kernel has
// copied the name by then, ordinarily faulting it in before the read below.
//
// The exit tracepoint only carries the return value, so the prctl arguments are
// recovered from the task's entry pt_regs (preserved across the syscall).
SEC("tracepoint/syscalls/sys_exit_prctl")
int tracepoint__sys_exit_prctl(UNUSED void *ctx)
{
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  long ptregs_addr         = get_task_pt_regs(task);
  if (!ptregs_addr) {
    goto exit;
  }

  struct pt_regs regs;
  if (bpf_probe_read_kernel(&regs, sizeof(regs), (void *)ptregs_addr)) {
    goto exit;
  }

// prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
//       unsigned long arg5): for PR_SET_VMA_ANON_NAME, arg3 and arg4 are the start
//       and length of the mapping, and arg5 is the name.
#if defined(__x86_64__)
  u64 option   = regs.di;
  u64 arg2     = regs.si;
  u64 addr     = regs.dx;
  u64 len      = regs.r10;
  u64 name_ptr = regs.r8;
#elif defined(__aarch64__)
  // At exit x0 (regs[0]) holds the return value, arg1 is preserved in orig_x0.
  u64 option   = regs.orig_x0;
  u64 arg2     = regs.regs[1];
  u64 addr     = regs.regs[2];
  u64 len      = regs.regs[3];
  u64 name_ptr = regs.regs[4];
#else
  #error unsupported architecture
#endif

  if (option != PR_SET_VMA || arg2 != PR_SET_VMA_ANON_NAME) {
    goto exit;
  }

  // The header starts a mapping, so it is page aligned, and the mapping holds at
  // least the header.
  if (addr == 0 || (addr & 0xfff) != 0 || len < OTEL_CTX_HEADER_SIZE) {
    goto exit;
  }

  // A NULL name removes the mapping's name: it doesn't announce anything.
  if (!name_ptr) {
    goto exit;
  }

  u32 pid = 0;
  u32 tid = 0;
  if (!get_pid_tgid(&pid, &tid)) {
    goto exit;
  }

  if (!bpf_map_lookup_elem(&reported_pids, &pid) && !pid_information_exists(pid)) {
    // Only report PIDs that we explicitly track. This avoids sending kernel worker PIDs
    // to userspace.
    goto exit;
  }

  // Read the VMA name from user-space. We only need 9 bytes ("OTEL_CTX" + NUL).
  // The read fails if the name's page isn't resident, since it can't fault it
  // in, and kernels without naming support return before reading the name.
  __attribute__((aligned(8))) char name[9] = {};
  bool name_read = !bpf_probe_read_user(name, sizeof(name), (void *)name_ptr);

  // Check for an exact "OTEL_CTX" match. We avoid bpf_strncmp (kernel 5.17+).
  // Instead, compare as a u64 for the 8 characters plus a byte check for the
  // NUL terminator. A readable name that doesn't match never announces a header.
  if (name_read && (*(u64 *)name != OTEL_CTX_SIGNATURE || name[8] != '\0')) {
    goto exit;
  }

  // Without a readable name, the header's signature identifies the announcement.
  // Publishers write the header just before announcing it, so it is very likely
  // resident.
  if (!name_read) {
    u64 signature = 0;
    if (bpf_probe_read_user(&signature, sizeof(signature), (void *)addr)) {
      goto exit;
    }
    if (signature != OTEL_CTX_SIGNATURE) {
      goto exit;
    }
  }

  if (bpf_map_update_elem(&otel_ctx_events, &pid, &addr, BPF_ANY)) {
    increment_metric(metricID_OtelCtxEventsErr);
    goto exit;
  }
  increment_metric(metricID_NumOtelCtxEvents);

exit:
  return 0;
}
