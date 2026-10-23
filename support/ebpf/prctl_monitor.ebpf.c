// This file contains the code for the tracepoint on prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)
// to detect when a process names an anonymous memory mapping "OTEL_CTX".

#include "bpfdefs.h"
#include "tracemgmt.h"

#include "types.h"

// prctl constants from include/uapi/linux/prctl.h
#define PR_SET_VMA           0x53564d41
#define PR_SET_VMA_ANON_NAME 0

// tracepoint__sys_exit_prctl detects when a process names an anonymous VMA
// "OTEL_CTX" and reports the PID to user space with value false: user space
// only logs it and does not trigger a PID resynchronization.
//
// We hook syscall exit, not entry, so the resync runs after the kernel has applied
// the rename; otherwise user space could re-read /proc/<pid>/maps before
// "[anon:OTEL_CTX]" is visible and miss the freshly published context.
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
//       unsigned long arg5): we only need option, arg2 and arg5 (the name).
#if defined(__x86_64__)
  u64 option   = regs.di;
  u64 ret      = regs.ax;
  u64 arg2     = regs.si;
  u64 name_ptr = regs.r8;
#elif defined(__aarch64__)
  // At exit x0 (regs[0]) holds the return value, arg1 is preserved in orig_x0.
  u64 option   = regs.orig_x0;
  u64 ret      = regs.regs[0];
  u64 arg2     = regs.regs[1];
  u64 name_ptr = regs.regs[4];
#else
  #error unsupported architecture
#endif

  if (ret != 0) {
    // The syscall failed. So return early.
    goto exit;
  }

  if (option != PR_SET_VMA || arg2 != PR_SET_VMA_ANON_NAME) {
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
  __attribute__((aligned(8))) char name[9] = {};
  if (bpf_probe_read_user(name, sizeof(name), (void *)name_ptr)) {
    goto exit;
  }

  // Check for an exact "OTEL_CTX" match. We avoid bpf_strncmp (kernel 5.17+).
  // Instead, compare as a u64 for the 8 characters plus a byte check for the
  // NUL terminator.
  if (*(u64 *)name != *(u64 *)"OTEL_CTX" || name[8] != '\0') {
    goto exit;
  }

  // Bypass report_pid: no rate limit bookkeeping (it would throttle real sync
  // events for this PID) and no user space wakeup. The periodic pid_events drain
  // picks the entry up. BPF_NOEXIST keeps a pending sync event (true) intact.
  u64 pid_tgid = ((u64)pid << 32) | tid;
  bool value   = false;
  if (!bpf_map_update_elem(&pid_events, &pid_tgid, &value, BPF_NOEXIST)) {
    increment_metric(metricID_NumSyncsFromPrctl);
  }

exit:
  return 0;
}
