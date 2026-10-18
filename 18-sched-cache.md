# Chapter 18 — Scheduler cache accounting: a write that outlives its `mm` (CVE-2026-98385)

Goal of this chapter: watch the *same endgame* as chapter 17 get rebuilt on a
completely different bug — and learn two things along the way. First, how a
kernel hot path borrows a lifetime it does not own (`p->mm` without a
reference). Second, a subtlety in the scheduler that lets you choose exactly
*whose* accounting writes your data: `account_mm_sched()` charges `rq->curr`,
the task actually running on a CPU — not the task whose dequeue triggered the
update. The exploitation target here is Arch Linux; the lesson is that the
method is not tied to a distribution, only to features and topology.

Material: `InfinityCore/sched/README.md` and
`InfinityCore/sched/CVE-2026-98385-arch.c` (14k lines — read the README's map,
not the whole file). Target: Arch Linux `7.2.4-arch1-2`. Introduced by
`df0d98475954`, fixed by `28f9c0e0a0b9` + `b636fef85bda`.

## 1. Background: `CONFIG_SCHED_CACHE`

`CONFIG_SCHED_CACHE` is a scheduler feature that keeps tasks sharing an
address space on the same Last Level Cache (LLC): each `mm_struct` carries

```c
struct sched_cache_stat {
    struct sched_cache_time __percpu *pcpu_sched;   // <- the per-CPU part
    raw_spinlock_t lock;
    unsigned long epoch;
    ...
} ____cacheline_aligned_in_smp;

struct sched_cache_time {
    u64 runtime;
    unsigned long epoch;
};                                                  // 16 bytes
```

Two gates before any of this runs:

- **Code/config:** `CONFIG_SCHED_CACHE=y` (plus a sysctl, default on).
- **Hardware topology:** `sched_cache_present` is only set when a scheduling
  partition has **more than one LLC**. The check `sd_in_multi_llcs()` (see
  `kernel/sched/topology.c`) requires the highest `SD_SHARE_LLC` domain to
  contain at least two CPUs *and* some wider parent domain to exist. One giant
  LLC → disabled; one CPU per LLC → disabled.

The PoC's environment is four vCPUs, `2 sockets × 2 cores`: CPUs 0/1 share LLC
A, CPUs 2/3 share LLC B. On a single-LLC VM the bug is simply not reachable —
a reminder that "can I trigger this?" includes asking about your *machine*,
not just your kernel.

## 2. The bug

The hot path reads the running task's `mm` and derives a per-CPU address from
it:

```c
struct mm_struct *mm = p->mm;                              /* no mmget() */
...
pcpu_sched = per_cpu_ptr(mm->sc_stat.pcpu_sched, cpu_of(rq));
scoped_guard (raw_spinlock, &rq->cpu_epoch_lock) {
    __update_mm_sched(rq, pcpu_sched);
    pcpu_sched->runtime += delta_exec;                     /* 8-byte RMW */
    ...
}
```

Two facts about the caller (`update_se()`): the task passed in is `rq->curr`
(the currently running task), and between computing `pcpu_sched` and the
guarded updates it must **acquire a lock** — time in which another CPU can
run `exec()` on the task that owns the `mm`, swap `tsk->mm`, and drop the old
address space. `__mmdrop()` → `mm_destroy_sched()` → `free_percpu()`. The
saved `pcpu_sched` is now a dangling pointer, and the guarded block proceeds
to write:

- `pcpu_sched->runtime += delta_exec` — 8 bytes at `+0`;
- the epoch alignment code — 8 bytes at `+8` (`epoch`), updated to "catch up"
  with the runqueue's epoch.

The PoC aims at `+12`: the **upper 32 bits of `epoch`**. Why a 32-bit window
matters: the allocation it is about to overlap is a **4-byte futex reference
counter** (the same `mm->futex_ref` per-CPU counters from chapter 17).

The exec side, from `fs/exec.c`: `exec_mmap()` swaps `tsk->mm` under the task
lock; `setup_new_exec()` → `exec_mm_put_old()` → `mmput()`; final `mm_count`
drop → `__mmdrop()` → `free_percpu(mm->sc_stat.pcpu_sched)`. No lock the
scheduler holds pins that lifetime.

The fix is two commits, and the split is the lesson:

1. `28f9c0e0a0b9` — split the statistics out of `mm_struct` into
   `struct sched_cache_group`, with its own `refcount_t` and RCU head. *Not
   enough alone*: the access still goes through `p->mm->sched_cache_grp`.
2. `b636fef85bda` — give each `task_struct` a `sched_cache_grp` reference and
   update it on fork/exec/exit, so `account_mm_sched()` no longer follows
   `p->mm` at all; RCU keeps the group alive while the sched code reads it.

Separating a lifetime is step one; *re-pointing every accessor* is step two.
If you ever audit a fix like this, check both.

## 3. The exploit

### 3.1 Stage 1: aim a stale epoch at a futex counter

Roles: CPU 0 = per-CPU allocator grooming; CPU 1 = **setter** (the attacker
calling `sched_setattr()`); CPU 2 = **trampoline** (a task that execs, and
whose `mm` will be captured) running on `rq2`, with a queued **wakee**; CPU 3
= timing/futex race.

- Grooming: fill low free slots, then free **four consecutive 4-byte objects**
  (futex refs) to open a 16-byte aligned hole; the trampoline's first exec
  (which allocates scheduler stats) drops its `sched_cache_time` there.
- The setter calls `sched_setattr()` on the wakee queued on CPU 2. The dequeue
  path runs `update_curr()` → `update_se()` → `account_mm_sched(rq2,
  rq2->curr, ...)`. `rq2->curr` is the **trampoline**. The setter has now
  steered a write onto a task it does not control... except it *is* the
  trampoline's mm that gets captured.
- The setter computes `pcpu_sched` from the trampoline's `old_mm`, then
  blocks on `rq2->cpu_epoch_lock`. The trampoline now execs **again**: new
  `mm`, old `mm` freed, scheduler object freed and reused.
- Layout of the reused 16-byte lane: three postfill refs live at `+0/+4/+8`;
  the new exec image's 8-slot futex hash reference sits at `+12` (value 1).
  So the 64-bit stale `epoch` reads `0x0000000100000000` — the upper half is
  the futex ref.
- The setter resumes and writes `epoch += n` (catch-up to the current small
  runqueue epoch): the upper 32 bits change from 1 to 0. The futex
  reference counter is silently zeroed — nothing else in the stale object is
  touched.

### 3.2 Stage 2: from zero ref to `-1` — the "negative reservoir"

A `CLONE_VM` child expands the corrupted hash 8 → 262,144 slots. The fold
`__futex_ref_atomic_end()` sums the per-CPU counters (the corrupted one
contributes 0 instead of 1) and computes
`atomic_long_add_return(count - LONG_MAX - 1)`: a valid state would leave 0
after adding `count = 1`; here `count = 0`, so the atomic reference becomes
**`-1`**.

`futex_ref_is_dead()` treats only exactly **0** as dead, so the resize child
does **not** pivot and stays waiting; the visible slot count stays 8. The PoC
verifies exactly that (`result == LONG_MIN`, slots still 8 before and after)
as its oracle: the atomic ref is now a bomb waiting for the `inc_not_zero()`
mismatch of chapter 17.

### 3.3 Stage 3: the late PI waiter

Same construction as chapter 17, now with this manufactured `-1`:

- a target gets a reference while `-1 → 0` (the increment "succeeds"), then is
  delayed **before** linking itself into the bucket;
- the selector looks up another futex, sees the atomic exactly 0, declares the
  hash dead, `futex_rehash_private()` moves only *already-linked* waiters to
  the new table — missing the target — publishes the new table, and
  `kvfree_rcu()`s the old one;
- the target then enters bucket 0 of the old hash; its `q->lock_ptr` now
  points into memory that is about to be a pipe ring.

Checks: `EDEADLK` from the PI owner cycle (target really waits), `FUTEX_WAKE`
on the *new* table returns 0 and the target stays asleep (it really did not
move).

### 3.4 Stages 4–5: the same pipe-ring endgame, aimed at `newgrp`

This part is deliberately the chapter 17 machine, rebuilt:

- 11 hash-flusher `mm`s + the target = 12 objects push the RCU sheaf's actual
  free; 4 workers × 15 waves × 16 pipes = 960 pipes; ring 2 → 16 slots
  (`16 × 40 = 640` bytes, `kmalloc-cg-1k`); alias:
  `queues[0].waiters` at object `+64` = `pipe_buffer[1].flags` at ring `+64`;
- one byte written/read per pipe moves the ring index to 1; then `splice()`
  the byte **just before the ELF entry** of `/usr/bin/newgrp` (setuid root);
- `SIGKILL` the target → cleanup walks the stale `q->lock_ptr` →
  `__futex_unqueue()` → `futex_hb_waiters_dec()` → `flags` `0 → 0xFFFFFFFF`,
  which contains `PIPE_BUF_FLAG_CAN_MERGE`;
- pipe writes: **16 bytes first to every pipe, hash-verify the file's
  intermediate state; then 29 more bytes** (45-byte stub total), verify
  again. Only the corrupted pipe merges into the page cache of `newgrp`.

Then the chapter 17 finish, restated: a payload child is forked *before* the
parent sets `PR_SET_NO_NEW_PRIVS`, so it can still gain privilege from the
setuid bit. It `execve`s `/usr/bin/newgrp`; the stub at the ELF entry
`execveat(AT_EMPTY_PATH)`s the PoC from reserved FD 198. The restarted PoC
sees `uid=1000, euid=0`, does `setgroups(0)` + `setresgid/setresuid(0,0,0)`,
**restores the original 45 bytes** of `newgrp`, `fchmod`s the saved mode,
`fsync`s, re-verifies the original hash, and launches a root shell.

## 4. What this chapter adds to your toolbox

| technique | why it generalizes |
|---|---|
| borrowed lifetime, no reference | `p->mm` read without `mmget()`/RCU and used after a sleeping acquisition; ask of every hot path: *what keeps this pointer's object alive while I wait?* |
| `rq->curr` vs the queued task | the accounting target is the *running* task — read the actual caller before assuming whose data you corrupt; steerability like this is gold |
| feature/topology gates | reachability includes config (`CONFIG_SCHED_CACHE`), sysctl, and CPU topology (two LLCs). Check the box before you check the code |
| per-CPU allocator as a shared canvas | 16-byte scheduler records and 4-byte futex refs are neighbors in the same per-CPU world; cross-subsystem reuse beats same-cache reuse |
| chained bugs | the PoC does not corrupt a `cred` directly: it *manufactures the precondition* for the chapter 17 bug (a `-1` futex ref). A write primitive is a key; a second bug is a lock it can open |
| fix in two commits | struct separation + accessor re-pointing; a lifetime fix that leaves the old accessor is not a fix |

## Hands-on

1. Read `InfinityCore/sched/README.md` §"Background"–§"Exploit", then map
   callouts `[1]`–`[22]` to the stages above. (Skip the 14k-line PoC except
   for targeted greps below.)
2. Does *your* kernel even have this feature?

   ```sh
   grep -i "SCHED_CACHE" /boot/config-$(uname -r)
   lscpu | grep -iE "^Socket|Core|Thread|NUMA|L3|L2"
   ```

   If the config symbol is absent (likely on a 6.x Ubuntu box), that alone
   settles reachability. The writeup's target is Arch, where it was enabled.
3. The fixed code in the big tree:

   ```sh
   grep -n "sched_cache_grp\|sched_cache_group" \
       /home/hp/lpe-study/linux/kernel/sched/fair.c \
       /home/hp/lpe-study/linux/include/linux/sched.h | head -20
   grep -n "sd_in_multi_llcs" /home/hp/lpe-study/linux/kernel/sched/topology.c
   ```

   Find `sched_cache_group_get/put`, the RCU free callback, and the
   `rcu_dereference_all(p->sched_cache_grp)` line inside `account_mm_sched()`.
   Which of the two fix commits does each belong to?
4. In the PoC, find the constants and confirm the two-write stub split:

   ```sh
   grep -n "SC_FILLER_COUNT\|PIPE_BANK_TOTAL_PIPES\|SC_TARGET_PATH" \
       /home/hp/lpe-study/InfinityCore/sched/CVE-2026-98385-arch.c | head
   grep -n "PAYLOAD_STUB_BYTES\|payload_handoff_entry_stub" \
       /home/hp/lpe-study/InfinityCore/sched/CVE-2026-98385-arch.c | head
   ```

5. Paper exercise: write out the 16-byte lane as bytes before and after the
   stale write. Start from
   `[ref][ref][ref][futex-ref=1]` and show what `epoch += 1` (read-modify-write
   of 8 bytes at `+8`) does for each value of `n` that only changes the high
   dword by 1. Confirm the futex ref ends at 0.

## Checkpoint

1. What exactly does `account_mm_sched()` borrow without a reference, and
   which lock acquisition gives the race its window?
2. Why is the write target `rq->curr` and not the task being
   `sched_setattr`'d — and how does the exploit use that?
3. Which two environment properties must hold for the vulnerable path to
   execute at all? What happens on a 4-CPU single-LLC VM?
4. Why does zeroing one 4-byte per-CPU futex reference turn the hash's atomic
   reference into `-1`, and why does `-1` survive
   `futex_ref_is_dead()`?
5. Why does the rehash during the pivot *miss* the target waiter, and what
   does the target's `q->lock_ptr` point to afterwards?
6. The chapter 17 and chapter 18 exploits share their entire second half.
   What is different — and what does that say about how exploit primitives
   compose across subsystems?
