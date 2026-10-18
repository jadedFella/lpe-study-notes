# Chapter 15 — The sigqueue UAF: the same exec, a different container (CVE-2026-98256)

Goal of this chapter: meet the *other* bug that was fixed right next to ours.
It triggers through the same non-leader `exec()` trick, and many of its pieces
will look familiar — but the container that keeps the stale pointer is a linked
list instead of an RB tree, the exploit needs a real race, and the endgame is a
control-flow hijack instead of a data write. This is Part D, so we now practice
the chapter-14 method on the other bugs in `InfinityCore/`.

Material for this chapter: `InfinityCore/signal/README.md` (root cause and
exploit walk) and `InfinityCore/signal/CVE-2026-98256-ubuntu.c` (the PoC).
Target of the writeup: Ubuntu 26.04, `7.0.0-30-generic`, four vCPUs.
Introduced by `fb3bbcfe344e`, fixed by `d2710c8d938a`.

## 1. Background: two queues per process

A signal delivered *to the process* (your `kill $pid`) goes into the
**shared pending** queue of `signal_struct`. A signal delivered *to a specific
thread* (your `tgkill`) goes into that `task_struct`'s **private pending**
queue. Chapter 2 built this model; one detail matters here:

- each queue is a pending bitmask plus a list of `struct sigqueue` objects;
- a `SIGEV_THREAD_ID` POSIX timer **embeds** its `struct sigqueue` in the
  `k_itimer` (`tmr->sigq`), and linking it into a queue is what finally
  delivers the timer signal;
- while the target signal is blocked, that `sigq` just *sits* in the queue —
  and the `k_itimer` stays alive because the queued signal holds a reference.

And one detail from chapter 5: when a non-leader calls `exec()`, `de_thread()`
**exchanges the thread IDs**. The old leader's TID becomes the exec thread's
TID; the `struct pid` that timers point at now resolves to the exec thread.

## 2. The bug, step by step

The writeup's vulnerable kernel does this:

1. The old leader calls `exit()`. `exit_signals()` sets `PF_EXITING` — but the
   vulnerable kernel (a) does **not** drain the task's private pending queue
   yet, and (b) does **not** refuse new `PIDTYPE_PID` signals for an exiting
   task. A zombie leader can keep accumulating private pending signals.
2. The surviving worker queues up to 20,000 `SIGEV_THREAD_ID` timer signals at
   the *old leader's TID*. They sit in the zombie's private pending queue.
3. The worker calls `execve`. `de_thread()` runs its PID exchange and then
   `release_task(leader)` removes the old leader. Its cleanup calls:

   ```c
   flush_sigqueue(&p->pending);          // <= no sighand->siglock held!
   ```

   This is the second half of the bug: private pending queues were considered
   unreachable once `PF_EXITING` was set, so the flush skips the lock. But the
   queue *is* reachable — through the exchanged PID that now points at the
   exec thread.
4. `flush_sigqueue()` detaches each entry with `list_del_init()`, which is
   **two separate stores**:

   ```c
   static inline void INIT_LIST_HEAD(struct list_head *list)
   {
       WRITE_ONCE(list->next, list);   // (1)
       WRITE_ONCE(list->prev, list);   // (2)
   }
   ```

   Between (1) and (2), `q->next == q` but `q->prev` still points into the old
   queue. A timer callback (`posixtimer_send_sigqueue`) that runs exactly in
   that window sees `list_empty(&q->list)` as **true** (`list_empty` reads only
   `next`), looks up its target with `posixtimer_get_target()` — and finds the
   *live exec thread* through the exchanged PID. It then links the same `q`
   into the exec thread's private pending queue.
5. Store (2) runs: `q->prev = q`. The exec thread's queue still links to `q`,
   but `q->prev` points to itself — the list is corrupt.
6. A *successful* exec later cleans timer signals in `__flush_itimer_signals`.
   The corrupted entry fails the `CONFIG_LIST_HARDENED` check, but because
   `CONFIG_BUG_ON_DATA_CORRUPTION` is off, the unlink is skipped and execution
   continues. The reference is dropped anyway, and the timer is freed with
   `kfree_rcu(tmr, rcu)` — while the freed `sigq` is **still linked from the
   new leader's pending queue**.

That is the UAF: one object, two lifetimes again. The `k_itimer`/`sigq` is
freed, but the pending list is a container that holds no reference and was not
told.

> **Compare with our bug:** same trigger family (non-leader `exec()` +
> `de_thread()` PID exchange), same free (`kfree_rcu`), same missing cleanup.
> Different container: a `sigqueue` list entry instead of a timerqueue RB node.
> And note the fix order: `d2710c8d938a` (this bug) is the direct parent of
> `acb03d388181` (our bug) — the two fixes landed back to back.

## 3. The exploit

### 3.1 Racing the flush

The race window is *two instructions wide*, so the PoC manufactures
interrupts:

- worker and lockless flush both pinned to CPU0;
- the worker creates the timer spray, rearms most of it far into the future,
  and reschedules ~12,288 of them in groups around the `execveat` call;
- CPUs 2 and 3 fire `membarrier` IPIs at CPU0, chopping execution into
  interrupt boundaries; the hrtimer callback lands between the two stores.

If the callback wins the window, one stale `SI_TIMER` entry survives in the
new leader's private pending queue.

### 3.2 A non-destructive oracle

How do you *observe* the queue without consuming the entry? `PTRACE_PEEKSIGINFO`
— a parent with the same uid stops the child and reads `siginfo` entries from
the private pending list **without dequeuing them and without dropping the
signal reference**. The PoC scans entry offsets (skipping the sentinel) and
looks for an `SI_TIMER` entry with its tag.

This is the same mindset as our "winner oracle" in chapter 10, but a different
tool: prefer observability that does not perturb the state you are observing.

### 3.3 Geometry, the freelist decode, and page reclaim

Target geometry: `sizeof(struct k_itimer)` = `0x180`, `sigq.list` at `0x88`,
`hrtimer.function` at `0x108`. `mnt_cache` has the same object size and merges
with `posix_timers_cache`; an order-1 slab holds 21 objects, so
`slot = (addr & 0x1fff) / 0x180` is valid from 0 to 20 and the slab base is
8 KiB-aligned. The preserved freelist word sits at `0xb0`, which overlaps
`sigq.info + 16` — i.e. a word the oracle can read back.

That overlap yields a leak in two reads:

1. while the freed target is still the slab's freelist head: the oracle reads
   the **encoded** next-free pointer out of word 16;
2. the PoC causes the slot to be freed once more as the freelist *tail*, and
   reads the encoded **NULL** pointer from the same word.

SLUB obfuscates freelist pointers as `ptr ^ random ^ address`. Same address,
same random → the XOR of the two reads is the raw address of the next object.
The PoC validates canonical range, `0x180` alignment, and slot ≤ 20.

Page reclaim (chapter 13 skills, applied here): free the slab's core region
while keeping an outer guard band alive so the order-1 slab cannot coalesce
into a larger buddy block; push leftover objects out of RCU shelving with
filler allocations; then flood with up to 8,192 pipe pages carrying markers
(serial + slot). Each candidate page is checked through the oracle; when a
marker shows up at the stale `siginfo`, the winning pipe is drained and
`io_setup(1)` re-claims the same physical page as an **AIO ring mapped into
user space**. The PoC then verifies through the oracle that a marker written
in the user mapping is visible at the stale pointer — proof that user space and
the freed `k_itimer` page are the same page.

KASLR: if the stale slot is in the lower half (0–10), the writeup reads a
surviving `hrtimer.function` from the adjacent upper page, still via the
oracle. If the slot is in the upper half (11–20), that page was reclaimed, so
it instead reads `posix_timer_fn` at offsets `0x108`/`0x288` of a nearby
`posix_timers_cache` slab and accepts the slide only after 2 MiB-alignment
checks.

### 3.4 Fake queue → control flow → root

Now the PoC builds a fully linked cycle in the reclaimed pages: stale entry
`S`, fake queue entry `Q`, decoy `D` (all links agree, so `LIST_HARDENED`
checks pass). `S` gets signal number 0 (skipped by the walk), `Q` gets
`SIGQUEUE_PREALLOC` + `SI_TIMER`, and `D` carries the same number as `Q`. `Q`
is interpreted by `container_of()` as the `sigq` embedded in a fake
`k_itimer`, so the delivery path calls:

```c
timr->kclock->timer_rearm(timr);      // indirect call through attacker data
```

The fake `k_clock`'s `timer_rearm` is a **JOP gadget** in the target kernel
(pre-slide `0xffffffff81cb2d20`) that loads `init_cred` and a pivot pointer
from the fake timer and branches into `commit_creds()`. The gadget returns
normally into signal delivery afterwards — so the kernel keeps running as if
nothing happened, but the current task now has root credentials.

To reach the fake entry, the PoC lowers `RLIMIT_SIGPENDING` to 0. An `SI_USER`
real-time signal to itself then fails its `sigqueue` allocation — but still
sets the pending *bit*. `rt_sigtimedwait` now walks the queue to find the entry
for that bit, finds `Q`, and runs the timer-delivery path. After verifying
`getuid()`/`geteuid()` are 0, it `clone()`s a child (fresh, clean pending
queue), which restores rlimits/dispositions and spawns the shell. The
corrupted task is **parked forever** on a futex — exactly like the "winner"
thread of our bug — and the controller keeps the AIO ring and pipes alive so
the fake objects stay mapped.

## 4. What this chapter adds to your toolbox

| technique | why it generalizes |
|---|---|
| `list_del_init` is two stores | any lockless reader can observe a half-unlinked list node; find which readers are allowed to run without the lock |
| non-destructive oracle (`PTRACE_PEEKSIGINFO`) | observing a corrupted structure beats consuming it; look for syscalls that *copy out* instead of *take* |
| freelist XOR decode | freed objects can leak; the encoding reuses randomness that cancels when you XOR two reads from the same slot |
| interrupt-boundary racing (`membarrier` IPIs) | when a window is 2 instructions wide, you don't wait for luck — you manufacture preemption/interrupts |
| `RLIMIT_SIGPENDING=0` | a *failed allocation* can still take a state-changing path; error paths are reachable states, not dead ends |
| indirect call from reclaimed data | a UAF object that is reinterpreted by a dispatcher (`container_of` + function pointer) gives control flow without any ROP setup |

## Hands-on

1. Read `InfinityCore/signal/README.md` §"Root Cause" and §"Exploit" next to
   the callouts `[1]`–`[16]`; map each one to a paragraph above.
2. Look at the *fixed* version we conveniently have locally — `d2710c8d938a`
   (the fix commit of this bug) is exactly the tree in `kernel-src/pre-fix/`:

   ```sh
   grep -n "flush_sigqueue\|exit_signals" /home/hp/lpe-study/kernel-src/pre-fix/kernel/exit.c
   sed -n '300,315p' /home/hp/lpe-study/kernel-src/pre-fix/kernel/exit.c
   ```

   The comment tells you the new contract: `tsk->pending` is flushed in
   `exit_signals()` (under the lock), and `release_task()` may only flush the
   shared queue locklessly.

3. In the big `linux/` tree, find the three pieces of the fix:

   ```sh
   grep -n "task_can_queue_signal" /home/hp/lpe-study/linux/kernel/signal.c
   grep -n "sigqueue_dequeue_pending\|flush_sigqueue_list" /home/hp/lpe-study/linux/kernel/signal.c
   sed -n '3195,3230p' /home/hp/lpe-study/linux/kernel/signal.c
   ```

   Read `task_can_queue_signal()`, its use in `__send_signal_locked()` and
   `posixtimer_send_sigqueue()`, and the `exit_signals()` lock scope that now
   detaches the private queue. Which single sentence from §2 does each hunk
   implement?

4. In `InfinityCore/signal/CVE-2026-98256-ubuntu.c`, find the oracle plumbing:
   `grep -n "PEEKSIGINFO\|peeksiginfo" InfinityCore/signal/CVE-2026-98256-ubuntu.c`
   and confirm it only reads (`nr = 1`, `off` is an index, nothing is drained).

## Checkpoint

1. Why was `flush_sigqueue(&p->pending)` allowed to run without
   `sighand->siglock`, and what assumption did that encode?
2. What are the exact two stores in `list_del_init()`, and why does the race
   need an interrupt *between* them?
3. `list_empty()` reads only `next`. Give the three-step sequence in which
   that becomes a wrong answer here.
4. After the corruption, why does a *successful* exec still free the timer
   without fixing the pending list?
5. What makes `PTRACE_PEEKSIGINFO` a good oracle, and what would be a bad
   alternative?
6. Explain in one sentence why `RLIMIT_SIGPENDING = 0` helps the attacker.
7. Why does the PoC leave the corrupted task parked instead of exiting it
   after winning?
