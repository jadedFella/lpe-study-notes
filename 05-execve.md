# Chapter 5 — `execve`: the world's most complicated syscall

Goal of this chapter: understand the one syscall in this story. By the end you
should be able to explain *why* a non-leader thread that calls `execve()` ends
up owning the old leader's PID, and *why* a `struct pid` that a timer stored
can stop pointing at any task. That single fact is what makes the whole
exploit possible.

## 1. What userspace thinks happens

`execve(path, argv, envp)` replaces the running program with another one. Same
process, same PID (usually), fds stay open unless `CLOEXEC`, signal handlers
reset, credentials may change for setuid binaries, and the address space is
thrown away and replaced. From a shell's point of view nothing happens to the
PID; from the scheduler's point of view nothing new is created.

## 2. The kernel's problem: threads

The *image* (address space, registers, stack) is per-thread; the *process*
(TGID, signal struct, fd table...) is shared by all threads. `execve` builds a
new image. If five threads share the old one and only one of them execs, the
other four can't stay: they are running code from an address space that no
longer exists. So `execve` is defined as: **all threads other than the caller
are destroyed first**. In a half-exec'd process, some threads would run old
code against new process state — impossible to reason about, so the kernel
doesn't allow it.

This is why `execve` contains so much machinery: it has to turn "one thread of
a group" into "the whole process, alone".

## 3. The call chain

```
syscall execve
 └ do_execveat_common              (fs/exec.c:1883)
    └ bprm_execve                  (fs/exec.c:1829)
       └ exec_binprm               (fs/exec.c:1780)
          └ search_binary_handler  (fs/exec.c:1746)
             └ ELF load_binary
                └ begin_new_exec   (fs/exec.c:1124)
                   ├ bprm->point_of_no_return = true   (1149)
                   ├ de_thread(me)                     (1152)  <-- identity surgery
                   ├ unshare_files / do_close_on_exec ...
                   ├ exec_mmap(bprm)                   (1199)  <-- killable waits
                   ├ posix_cpu_timers_exit(me)         (1211) } the old
                   ├ exit_itimers(me)                  (1213) } cleanup site
                   └ ... the rest of exec
```

Two line numbers to keep in your head: **1152** (`de_thread`) and **1199–1215**
(`exec_mmap` followed by the timer cleanup). Chapter 7 is entirely about their
ordering.

## 4. The point of no return

`begin_new_exec` sets the flag at line 1149, right before `de_thread` — the
comment (1138–1143) explains:

> This tracepoint marks the point before flushing the old exec where the
> current task is still unchanged, but errors are fatal (point of no return).

Once it is set, **every error is fatal**. Here is how `bprm_execve` enforces
it (fs/exec.c:1866–1874):

```c
out:
	/*
	 * If past the point of no return ensure the code never
	 * returns to the userspace process.  Use an existing fatal
	 * signal if present otherwise terminate the process with
	 * SIGSEGV.
	 */
	if (bprm->point_of_no_return && !fatal_signal_pending(current))
		force_fatal_sig(SIGSEGV);
```

Read that twice: after the flag flips, a failure doesn't return an error code
to your program. The process *dies*. That behavior turns "a rare error path"
into "a death path" — and death has its own cleanup code (chapter 6), which is
where the bug hides.

## 5. `de_thread()`: killing the siblings and swapping identities

`de_thread(tsk)` (fs/exec.c:922) is called with `tsk` = the calling thread
("me"). Walk through it:

1. **Fast path.** If the thread group has no other threads, jump to
   `no_thread_group` and return.
2. **Refuse during group exit** (935–942): if the group is already exiting or
   another exec is in progress (`sig->group_exec_task`), return `-EAGAIN`.
3. **Kill the others** (944–945):

   ```c
   sig->group_exec_task = tsk;
   sig->notify_count = zap_other_threads(tsk);
   ```

   `zap_other_threads` sends SIGKILL to every other thread in the group and
   counts them.
4. **Wait for them to become zombies** (949–956), a `TASK_KILLABLE` sleep
   loop. Each sibling's exit decrements `notify_count` and wakes us
   (`__exit_signal`, kernel/exit.c:184–185). If a fatal signal arrives while
   waiting, `goto killed` → set `group_exec_task = NULL` → return `-EAGAIN`.
5. **If we are not the leader** (964+), we also wait for the leader's
   `exit_state` to become a zombie (975–983), then perform the identity swap
   described next.

### The identity swap (fs/exec.c:995–1035)

```c
exchange_tids(tsk, leader);                 /* pid.c:436 */
transfer_pid(leader, tsk, PIDTYPE_TGID);
transfer_pid(leader, tsk, PIDTYPE_PGID);
transfer_pid(leader, tsk, PIDTYPE_SID);
...
tsk->group_leader = tsk;
leader->group_leader = tsk;
tsk->exit_signal = SIGCHLD;
leader->exit_signal = -1;
leader->exit_state = EXIT_DEAD;
release_task(leader);
```

Why? The process's user-visible PID *is the TGID*, and the TGID belonged to
the leader. If the leader must die and a thread takes over the process, that
thread must inherit the PID — otherwise `getpid()` would suddenly change,
which is forbidden for `execve`. So the two threads **swap TIDs**:
after `exchange_tids(B, leader)`, B's `pid` is the old leader's, and the dying
leader is left holding B's old per-thread PID. Then the leader is removed from
the world entirely by `release_task`.

`exchange_tids` itself (kernel/pid.c:436–455) is short:

```c
void exchange_tids(struct task_struct *left, struct task_struct *right)
{
	struct pid *pid1 = left->thread_pid;
	struct pid *pid2 = right->thread_pid;
	struct hlist_head *head1 = &pid1->tasks[PIDTYPE_PID];
	struct hlist_head *head2 = &pid2->tasks[PIDTYPE_PID];
	...
	/* Swap the single entry tid lists */
	hlists_swap_heads_rcu(head1, head2);
	/* Swap the per task_struct pid */
	rcu_assign_pointer(left->thread_pid, pid2);
	rcu_assign_pointer(right->thread_pid, pid1);
	/* Swap the cached value */
	WRITE_ONCE(left->pid, pid_nr(pid2));
	WRITE_ONCE(right->pid, pid_nr(pid1));
}
```

Names: before the call, B holds `P_t` ("tid pid") and leader holds `P_l`
("leader pid"). After the call, **B holds `P_l` and the leader holds `P_t`**,
and the `PIDTYPE_PID` task lists were swapped to match. A `struct pid` is a
name object: it can be attached to any task, or to none.

## 6. `release_task(leader)`: where `P_t` loses its task

`release_task` (kernel/exit.c:248) is the "reap" operation — the final,
irreversible destruction of a task. Near the top:

```c
thread_pid = get_pid(task_pid(p));      /* p = the old leader; now that is P_t */
```

then `__exit_signal(&post, p)` (272). Inside `__exit_signal`
(kernel/exit.c:158), under the sighand lock:

- `posix_cpu_timers_exit(p)` — cleans the *leader's own* timer queues. Ours is
  in B's records, not here; nothing happens to it.
- `__unhash_process(...)` — detaches the task from its PID lists. Because of
  the swap, the leader was the one (temporarily) named by `P_t`, so this is
  the moment `P_t`'s `PIDTYPE_PID` list becomes empty.

`pid_task()` (kernel/pid.c:466–477) is just a list-head read:

```c
struct task_struct *pid_task(struct pid *pid, enum pid_type type)
{
	struct task_struct *result = NULL;
	if (pid) {
		struct hlist_node *first;
		first = rcu_dereference_check(hlist_first_rcu(&pid->tasks[type]), ...);
		if (first)
			result = hlist_entry(first, struct task_struct, pid_links[(type)]);
	}
	return result;
}
```

Empty list → `NULL`. So from this point on: **`pid_task(P_t, PIDTYPE_PID)`
returns NULL**, even though `P_t` itself is still a live object (the timer
holds a reference to it — chapter 3).

## 7. `exec_mmap`'s killable waits — how to fail after 1149

`begin_new_exec` continues after `de_thread`: `unshare_files` (1163),
`do_close_on_exec` (1179), `set_mm_exe_file` (1186), then `exec_mmap` (1199).
`exec_mmap` (843) takes locks:

```c
	ret = down_write_killable(&tsk->signal->exec_update_lock);   /* 861 */
	if (ret)
		return ret;
	...
		ret = mmap_read_lock_killable(old_mm);               /* 871 */
		if (ret) { up_write(...); return ret; }
```

*Killable* means: if a fatal signal (like SIGKILL) is pending, these return
`-EINTR` instead of waiting. `begin_new_exec` then does `goto out` (1201) —
the timer cleanup lines 1211–1213 are skipped. And because of the point of no
return, `bprm_execve`'s `out:` block makes sure B never returns to userspace:
the pending SIGKILL kills it (or a forced SIGSEGV would).

Summary: **a SIGKILL delivered between `de_thread` and the cleanup lines is a
legal way to fail `execve` after the identity swap has already happened.**

## 8. What this does to timers

From chapter 3: a per-thread CPU timer stores `it.cpu.pid = task_pid(creator)`
— `P_t`, the creator's *thread* pid. A process-wide CPU timer stores
`task_tgid(creator)` instead. After the sequence above:

| timer kind | stored pid | after non-leader exec + leader reap |
|---|---|---|
| `CLOCK_THREAD_CPUTIME_ID` | creator's thread pid `P_t` | `pid_task()` = **NULL** |
| `CLOCK_PROCESS_CPUTIME_ID` | creator's TGID `P_l` | still resolves: `transfer_pid` moved the TGID to the execer |

That asymmetry is why this exploit must use the *thread* clock: only the
thread-level `struct pid` can be left with no task attached. Remember it; it
comes back in every remaining chapter.

## Hands-on

1. Write `execthread.c` and run it:

```c
/* gcc -pthread -o execthread execthread.c */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

static pid_t tid(void) { return syscall(SYS_gettid); }

static void *thread_fn(void *arg)
{
	printf("thread before exec: pid=%d tid=%d\n", getpid(), tid());
	execl("/proc/self/exe", "execthread", "after", NULL);
	perror("execl");
	_exit(1);
}

int main(int argc, char **argv)
{
	if (argc > 1) {
		printf("exec'd process:    pid=%d tid=%d\n", getpid(), tid());
		return 0;
	}
	printf("leader before:     pid=%d tid=%d\n", getpid(), tid());
	pthread_t t;
	pthread_create(&t, NULL, thread_fn, NULL);
	sleep(1);
	return 0;
}
```

   Expected: the thread's TID before exec differs from the PID; after exec the
   TID **equals the PID** — the thread took over the leader's identity. The
   leader disappears silently (killed by `de_thread`).

2. Run it under `strace -f -e trace=clone,execve` and find where the leader
   gets killed (you'll see the SIGKILL delivery to the non-execing thread).
3. Read (or re-read) in `fs/exec.c`: `de_thread` 922–1055. In `kernel/pid.c`:
   `exchange_tids` 436–455, `transfer_pid` 458–464, `pid_task` 466–477. In
   `kernel/exit.c`: `release_task` 248–320, `__exit_signal` 158–225.
4. Answer: the timer from chapter 3 stored `task_pid(current)`. After the
   sequence in this chapter, what exactly does that stored `struct pid` name
   — a task, a zombie, or nothing? Why doesn't the process-wide version have
   the same problem?

## Checkpoint

1. Why must `execve` destroy the other threads instead of letting them keep
   running?
2. What does `exchange_tids` swap — names only, or tasks too? (Both, but be
   precise about which is which.)
3. Why does `release_task(leader)` make `P_t` resolve to no task?
4. Which two waits inside `exec_mmap` can fail with `-EINTR` when SIGKILL is
   pending, and what does `point_of_no_return` say about that failure?
5. Why does the thread-CPU timer break here while the process-CPU timer does
   not?
