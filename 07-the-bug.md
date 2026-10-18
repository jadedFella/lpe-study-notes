# Chapter 7 — Assembling the bug: the exact sequence

Goal of this chapter: put chapters 3–6 together into the full, numbered
sequence of CVE-2026-98260. Every step cites code you have already read. At
the end, you should be able to reconstruct the ordering from memory, and to
say for each step *why it is required*.

## 0. The characters and the initial state

The process P has two threads:

- **L**, the thread-group leader (created by `fork`),
- **B**, a non-leader thread (created by `clone(CLONE_THREAD)`, i.e. what
  `pthread_create` uses).

B creates a timer:

```c
timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &tid);
timer_settime(tid, 0, &one_hour, NULL);
```

State after arming (all line references from chapters 3–4):

| thing | where | notes |
|---|---|---|
| object `O` | `P->signal->posix_timers` list | `O->it.cpu.pid = P_t` = **B's** `struct pid` |
| node `N` | `B->posix_cputimers.bases[2].tqhead` | `N.head = &B->...tqhead`, status `ARMED` |
| pid object `P_t` | `P_t->tasks[PIDTYPE_PID] = { B }` | resolves to B |

Nothing here is unusual. Every ingredient below is normal kernel behavior.

## 1. B calls `execve()`

- `begin_new_exec` sets `bprm->point_of_no_return = true` (fs/exec.c:1149).
  From this moment, any error kills the task (chapter 5 §4).
- `de_thread(B)` is called (fs/exec.c:1152).

## 2. `de_thread`: the other threads are removed

- `zap_other_threads(B)` sends SIGKILL to L (and any other threads) and
  counts them (`notify_count`).
- L runs `do_exit`. **L is not the last thread**, so `group_dead` is false and
  `exit_itimers` is *not* called (kernel/exit.c:959–972). The process's timers
  survive a sibling's death, exactly as designed.
- L becomes a zombie (`EXIT_ZOMBIE`); B observes it and proceeds.

State: everything from §0 is still true.

## 3. `exchange_tids(B, L)`: the fatal identity swap

fs/exec.c:1009 calls `exchange_tids(B, L)` (kernel/pid.c:436):

- the two `thread_pid` pointers are swapped,
- the `PIDTYPE_PID` task-list heads are swapped to match,
- the cached `task->pid` numbers are swapped.

After this call:

| who | `thread_pid` | numeric pid | `PIDTYPE_PID` list owns |
|---|---|---|---|
| B | `P_l` (leader's old pid) | the process's TGID | B |
| L | `P_t` (**B's old thread pid**) | B's old TID | L |

Then `transfer_pid(L, B, PIDTYPE_TGID/PGID/SID)` (1010–1012) moves the
process-level identities to B, and the `tasks`/`sibling` lists and
`group_leader` pointers are fixed up (1014–1018).

Note the ironic detail: **the timer's `P_t` now names L** — a zombie about to
be reaped.

## 4. `release_task(L)`: `P_t` becomes an orphan

fs/exec.c:1024–1035: `leader->exit_state = EXIT_DEAD; release_task(leader);`

Inside `release_task` (kernel/exit.c:248):

- `__exit_signal(L)` → `posix_cpu_timers_exit(L)`: cleans **L's own** timer
  queues. Our node is queued in B, so it is untouched.
- `__unhash_process` → `detach_pid(PIDTYPE_PID)`: L's hlist entry is removed
  from `P_t->tasks[PIDTYPE_PID]`, i.e. **`pid_task(P_t, PIDTYPE_PID)` returns
  NULL** from now on.
- The `struct pid` `P_t` itself survives: the timer holds a reference
  (`get_pid` at creation time), so the object isn't freed — it is just
  attached to no task.

This is exactly the state the kernel's own comment at
`posix-cpu-timers.c:497–506` draws: *"// Returns NULL / sighand =
lock_task_sighand(p)"*.

## 5. The killable tail: `exec_mmap` and the killer

Back in `begin_new_exec` (fs/exec.c:1155+): `unshare_files`, `do_close_on_exec`,
`set_mm_exe_file` — then `exec_mmap(bprm)` (1199). Chapter 5 §7: both
`down_write_killable` (861) and `mmap_read_lock_killable` (871) can return
`-EINTR` if a fatal signal is pending, and then:

```c
	retval = exec_mmap(bprm);
	if (retval)
		goto out;                       /* fs/exec.c:1201 */
```

How does the exploit hit this window? A separate *process* (created with
`CLONE_VM`, **not** a thread — it must survive `de_thread`) polls
`tgkill(tgid, old_tid, 0)` until it returns `ESRCH`. `ESRCH` proves that the
old TID no longer resolves → §3 and §4 are done. Then the killer sends
`SIGKILL` to the process. B is inside the exec critical section; the pending
SIGKILL interrupts one of the killable locks; `goto out`.

If the SIGKILL arrived *earlier* — while `de_thread` was still waiting — the
`killed:` path (fs/exec.c:1048–1054) returns `-EAGAIN` **before** the swap and
release. Then `P_t` still resolves to B, `posix_cpu_timer_del` can work, and
there is no bug. The timing is not a lottery; it is a required ordering
condition.

## 6. Death of B: `exit_itimers` frees the object

Because of `point_of_no_return` (chapter 5 §4), B cannot return to userspace
with an error. The pending SIGKILL kills it: `do_exit` runs.

- B is the **last live thread** (L is already `EXIT_DEAD`), so
  `group_dead = true` and kernel/exit.c:969–972 calls:

  ```c
  hrtimer_cancel(&tsk->signal->real_timer);
  exit_itimers(tsk);
  ```

- For our timer `O`, `exit_itimers` → `posix_timer_delete` →
  `posix_cpu_timer_del(O)` (posix-cpu-timers.c:574):
  - `timer_lock_sighand(O)`: `pid_task(P_t, PIDTYPE_PID)` is NULL → returns
    NULL. On the way out it fires the `WARN_ON_ONCE` (564) because
    `ctmr->head` is still set and the node is still queued — the kernel dumps
    a warning ("This should never happen!"); on a `panic_on_warn` kernel this
    alone is a denial of service.
  - `if (likely(p))` is false → **`disarm_timer` is skipped** → the node is
    never dequeued.
  - `put_pid(P_t); it_status = DISARMED; return 0;` — success as far as the
    caller is concerned.
- `posix_timer_unhash_and_free(O)` → reference drop →
  `posixtimer_free_timer(O)` → `kfree_rcu(O)` (posix-timers.c:442–448).

**State now:**

| thing | state |
|---|---|
| object `O` | freed (RCU-deferred); bytes may still look valid |
| node `N` | still linked in `B->posix_cputimers.bases[2].tqhead` |
| `O->it.cpu.head` | still `&B->...tqhead` (stale, in freed memory) |
| B | zombie, not yet reaped — its `task_struct` and queues live on |

The successful-exec cleanup block (fs/exec.c:1211–1213) never ran: exec failed
before reaching it.

## 7. Reap: the use-after-free moment

When B is finally reaped (`wait`/`waitid`, or the parent's delayed wait),
`release_task(B)` → `__exit_signal(B)` → `posix_cpu_timers_exit(B)`
(kernel/exit.c:171) → `cleanup_timers(&B->posix_cputimers)` →
`cleanup_timerqueue` on the SCHED base (posix-cpu-timers.c:605):

```c
while ((node = timerqueue_getnext(head))) {
	timerqueue_del(head, node);          /* node = N, inside freed O! */
	ctmr = container_of(node, struct cpu_timer, node);
	ctmr->head = NULL;
}
```

- `timerqueue_getnext` returns the leftmost node address — an address inside
  memory the kernel already freed.
- `timerqueue_del(head, N)` → `rb_erase_cached` reads `N`'s
  `__rb_parent_color` / `rb_right` / `rb_left` and writes through them
  (chapter 4 §7). Every byte it uses is attacker-relevant once the slot is
  reused.
- `ctmr->head = NULL` writes even more (offset 0x100 in a 0x180 object) into
  the freed slot — a free extra "you know where the object is" marker for the
  exploit.

If the slot hasn't been reused yet, the erase may silently "work" on stale
bytes — still a UAF, just a quiet one. If the slot has been reused, the kernel
is now reading/writing an object of a completely different type.
*This* is the primitive the rest of the exploit is built around.

## 8. Why every ingredient is required

| # | ingredient | where | why needed |
|---|---|---|---|
| 1 | `CLOCK_THREAD_CPUTIME_ID` | timer_create | only the thread-level pid can become an orphan; TGID survives exec |
| 2 | non-leader execer | de_thread 964 | leaders don't go through the exchange/release path |
| 3 | failure after `point_of_no_return` | exec_mmap 861/871 | skips the only *direct* dequeue (1211) |
| 4 | execer is the last thread | exit.c 959 | `do_exit` only calls `exit_itimers` when `group_dead` |
| 5 | delayed reap | wait/WNOWAIT | the node's queue (B's task_struct) must outlive the object |
| 6 | killable wait + well-timed SIGKILL | exec_mmap 861/871 | provides a legal failure point *after* the pid surgery |
| 7 | per-thread queue cleanup at reap | cleanup_timerqueue 605 | touches the node with no lookup at all |

Remove any row and the chain breaks. That's why this bug survived so long: it
needs all seven.

## 9. The fix

The fix commit `acb03d388181` ("exec: Cleanup POSIX timers right after
de_thread()") introduces `posixtimer_exec(me)`:

```c
/* siglock held */
posix_cpu_timers_exit(me);      /* direct dequeue — no pid lookup */
exit_itimers(me);               /* free objects */
flush_itimer_signals();
```

and calls it **immediately after `de_thread()`** — before `unshare_files`,
`set_mm_exe_file`, `exec_mmap`, and every other fallible step. Reasoning:

- `posix_cpu_timers_exit(me)` works directly on `me`'s queues, so it removes
  `N` while `O` is still allocated (the legal order).
- `exit_itimers(me)` then frees `O`; at this point the pid lookup may already
  fail, but the node is gone, so nothing stale remains.
- Because the call happens right after `de_thread`, `me` is guaranteed to be
  the only remaining thread: no other task can race with these queues.
- Any later exec failure can no longer leave a queued node behind, because
  the node was already removed at the earliest safe moment.

The old site (fs/exec.c:1209–1215) had the right *order* but the wrong
*position*: it was reachable only on success.

## Hands-on

1. **State-table exercise.** Copy this table and fill it from the source (one
   column per step). This is the best way to prove you own the sequence:

| step | `pid_task(P_t)` | `O` allocated? | node `N` queued? | B's state |
|---|---|---|---|---|
| initial (armed timer) | B | yes | yes | running |
| after `zap_other_threads` | B | yes | yes | running; L zombie |
| after `exchange_tids` | **L** | yes | yes | running |
| after `release_task(L)` | **NULL** | yes | yes | running |
| after SIGKILL/`-EINTR` | NULL | yes | yes | dying |
| after `exit_itimers(B)` | NULL | **no (freed)** | **yes** | zombie |
| after reap | NULL | no | removed via UAF | gone |

2. Open posix-cpu-timers.c:464–522 (the kernel's own comment) and map each
   paragraph to a step above. The developers wrote the bug's story down; you
   are just reading it with the correct names now (`switch_leader` in the
   comment = `exchange_tids` in the code).
3. Find `posixtimer_exec` in the fix commit and confirm it is called right
   after `de_thread`.
4. Answer: which single event turns the situation from "recoverable" into
   "too late" for the node? (`release_task(leader)` / the `detach_pid` inside
   `__unhash_process`.)

## Checkpoint

1. Why does B's `do_exit` see `group_dead == true` even though B was not the
   leader when this started?
2. Name the function that frees the object and the one that would have
   dequeued the node, and say which one skipped its work and why.
3. What does the killer's `tgkill(..., old_tid) -> ESRCH` observation prove,
   and why is that ordering required?
4. At reap, which structure still contains the stale node address, and why
   does `cleanup_timerqueue` trust it?
5. Why is the fix's position ("right after de_thread") more important than
   the fix's code?
