# Kernel LPE study notes — the POSIX CPU timer bug

A slow, from-zero walkthrough of `CVE-2026-98260-ubuntu.c` (a Linux kernel
local privilege escalation via a POSIX CPU timer use-after-free in `exec()`).

Written one chapter at a time, from first principles: processes and threads,
syscalls, `task_struct` / `signal_struct` / `struct pid` / `cred`, POSIX
timers, the timerqueue RB tree, `execve` and `de_thread`, the use-after-free,
and then the full exploit chain.

Part D (chapters 15–19) adds five sibling case studies from the same exploit
set — a sigqueue UAF in `exec()`, a page-table walker OOB in `mincore()`, a
private futex hash UAF, a scheduler cache accounting UAF, and a SLUB
partial-list race — with four different exploitation endgames.

Chapter 20 is an appendix on a different bug class: CVE-2026-43284
("DirtyFrag"), a networking page-cache write, and the Android chain that turns
it into an ephemeral root without unlocking the bootloader.

**Start here → [00-README.md](00-README.md)**

Reading order and suggested pace are in the index. New chapters are added as
the study progresses.

---
*Personal study notes. The analyzed exploit is third-party security research,
reproduced here for education only.*
