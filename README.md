# Kernel LPE study notes — the POSIX CPU timer bug

A slow, from-zero walkthrough of `CVE-2026-98260-ubuntu.c` (a Linux kernel
local privilege escalation via a POSIX CPU timer use-after-free in `exec()`).

Written one chapter at a time, from first principles: processes and threads,
syscalls, `task_struct` / `signal_struct` / `struct pid` / `cred`, POSIX
timers, the timerqueue RB tree, `execve` and `de_thread`, the use-after-free,
and then the full exploit chain.

**Start here → [00-README.md](00-README.md)**

Reading order and suggested pace are in the index. New chapters are added as
the study progresses.

---
*Personal study notes. The analyzed exploit is third-party security research,
reproduced here for education only.*
