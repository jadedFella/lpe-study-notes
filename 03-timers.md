# Chapter 3 — Timers: what `timer_create` really does, and where a CPU timer lives

Goal of this chapter: follow `timer_create(CLOCK_THREAD_CPUTIME_ID, ...)` from
the syscall down to the moment a tree node sits inside *your thread's* kernel
record. By the end you should be able to say which structure owns the timer
*object*, which structure owns the timer *node*, and why a `struct pid` sits
between them. That is the setup for the bug.

## 1. The userspace interface

Three syscalls matter:

```c
timer_create(clockid, sigevent, &timer);          /* create, get a handle */
timer_settime(timer, flags, &its, NULL);          /* arm it */
timer_delete(timer);                              /* remove it */
```

The `clockid` picks the time base. On x86-64 the numbers you will see in
`strace` are:

| id | name | meaning |
|----|------|---------|
| 0 | `CLOCK_REALTIME` | wall-clock time |
| 1 | `CLOCK_MONOTONIC` | time since boot |
| 2 | `CLOCK_PROCESS_CPUTIME_ID` | CPU time consumed by the whole process |
| 3 | `CLOCK_THREAD_CPUTIME_ID` | CPU time consumed by the calling thread |

The `sigevent` says what happens on expiry: send a signal (`SIGEV_SIGNAL`),
do nothing (`SIGEV_NONE`), or hand off to a thread (`SIGEV_THREAD`).

The exploit uses `CLOCK_THREAD_CPUTIME_ID`: the timer fires when *the calling
thread* has burned a given amount of CPU time. Remember that: the timer is
tied to a **thread**, not a process.

## 2. Inside `do_timer_create()`

The syscall handler is `SYSCALL_DEFINE3(timer_create, ...)`, which calls
`do_timer_create()` in `kernel-src/pre-fix/kernel/time/posix-timers.c:466`.
The pieces, in order:

1. **Pick the clock implementation.**
   `clockid_to_kclock(which_clock)` looks the number up in a table of
   `struct k_clock` objects (a struct of function pointers: `timer_create`,
   `timer_set`, `timer_del`, `clock_get`, ...). `CLOCK_THREAD_CPUTIME_ID` maps
   to `clock_thread` (posix-timers.c:1528).

2. **Allocate the object.** `alloc_posix_timer()`:

   ```c
   tmr = kmem_cache_zalloc(posix_timers_cache, GFP_KERNEL);
   ...
   rcuref_init(&tmr->rcuref, 1);
   ```

   Every timer object in the system comes from one dedicated slab cache,
   `posix_timers_cache`, sized for `sizeof(struct k_itimer)` (0x180 bytes on
   the exploit's target). Keep this in mind — chapter 13 is largely about this
   cache's memory reuse.

3. **Publish the handle.** `posix_timer_add()` assigns the `timer_t` ID you
   get back and inserts the object into a hash table so later syscalls can
   find it by ID. It also temporarily marks the timer invalid by storing
   `it_signal` with bit 0 set.

4. **Fill in the basics:** `it_clock = which_clock`, `kclock = kc`, the
   sigevent fields (`it_sigev_notify`, signal number and value).

5. **Call the clock-specific create hook:** `kc->timer_create(new_timer)`
   (posix-timers.c:544). For our clock that is `thread_cpu_timer_create()`,
   which *rewrites* the clock id to an internal encoding and then calls
   `posix_cpu_timer_create()` — section 3 and 4 below are all about these two
   functions.

6. **Make it visible.** At the very end, with locks held:

   ```c
   WRITE_ONCE(new_timer->it_signal, current->signal);   /* clears bit 0: valid now */
   hlist_add_head_rcu(&new_timer->list,
                      &current->signal->posix_timers);   /* posix-timers.c:562 */
   ```

   From this moment the object is on the **process-wide list**
   `signal_struct.posix_timers` — the list that the process-exit path walks.
   (That bit-0 "valid" flag is worth remembering: the exploit will show a fake
   timer whose `it_signal` has bit 0 set, so the kernel refuses to deliver a
   signal from it.)

So: the *object* is process-owned, even though our timer targets a single
thread. The thread-specific part comes next.

## 3. The internal clock encoding

Userspace sent `3`. The kernel needs an internal value that says
"per-thread, SCHED clock, target = me". That encoding is built by
`make_thread_cpuclock()` (`include/linux/posix-timers.h:24`) and decoded by
macros in `include/linux/posix-timers_types.h`:

```c
#define CPUCLOCK_PERTHREAD(clock) (((clock) & CPUCLOCK_PERTHREAD_MASK) != 0)
#define CPUCLOCK_WHICH(clock)     ((clock) & CPUCLOCK_CLOCK_MASK)

#define CPUCLOCK_PROF   0
#define CPUCLOCK_VIRT   1
#define CPUCLOCK_SCHED  2
```

`thread_cpu_timer_create()` sets:

```c
timer->it_clock = THREAD_CLOCK;   /* = make_thread_cpuclock(0, CPUCLOCK_SCHED) */
return posix_cpu_timer_create(timer);
```

and `THREAD_CLOCK` (posix-cpu-timers.c:1671) encodes **pid 0**, which means
"the calling thread". `CPUCLOCK_WHICH(it_clock)` for this value is
`SCHED = 2`. You will see `2` again as a queue index in section 5.

## 4. `posix_cpu_timer_create()` — the object remembers a thread

`kernel-src/pre-fix/kernel/time/posix-cpu-timers.c:386`:

```c
static int posix_cpu_timer_create(struct k_itimer *new_timer)
{
	...
	new_timer->kclock = &clock_posix_cpu;
	timerqueue_init(&new_timer->it.cpu.node);
	new_timer->it.cpu.pid = get_pid(pid);
	...
	return 0;
}
```

The `pid` on line 392 comes from `pid_for_clock(new_timer->it_clock, false)`,
which (line 57) resolves the encoded value:

```c
if (upid == 0)                      /* pid 0 = "self" */
	return thread ? task_pid(current) : task_tgid(current);
```

`task_pid(current)` is the calling thread's `struct pid`. `get_pid()` takes a
reference, so that `struct pid` object cannot be freed while the timer lives.

**But** a `struct pid` is only a name; the *task attached to it* can change
or disappear. Chapter 5 is entirely about `execve()` doing that. This stored
pid is exactly how the kernel later answers "which thread owns this timer?" —
via a lookup that is allowed to fail.

## 5. Arming: where the node lands

`timer_settime` → `posix_cpu_timer_set()` → `arm_timer()`
(posix-cpu-timers.c:649):

```c
static void arm_timer(struct k_itimer *timer, struct task_struct *p)
{
	struct posix_cputimer_base *base = timer_base(timer, p);
	struct cpu_timer *ctmr = &timer->it.cpu;
	...
	timer->it_status = POSIX_TIMER_ARMED;
	if (!cpu_timer_enqueue(&base->tqhead, ctmr))
		return;
	...
}
```

`timer_base()` (line 416) picks the queue:

```c
int clkidx = CPUCLOCK_WHICH(timer->it_clock);        /* = 2 (SCHED) */
if (CPUCLOCK_PERTHREAD(timer->it_clock))
	return tsk->posix_cputimers.bases + clkidx;          /* per-thread: task's own */
else
	return tsk->signal->posix_cputimers.bases + clkidx;  /* process-wide */
```

and `cpu_timer_enqueue()` (`include/linux/posix-timers.h:69`) does two things:

```c
ctmr->head = head;                      /* remember which queue */
return timerqueue_add(head, &ctmr->node);   /* insert the node */
```

For our timer, after arming:

- the **node** is in `task_struct.posix_cputimers.bases[2].tqhead` — a tree
  that lives inside the owning thread's kernel record;
- the object remembers the queue through `ctmr->head`;
- the expiry is "current thread CPU time + it_value" (the code samples the
  thread's consumed CPU time to compute it).

One timer, two live locations: the object on the process list, the node in
the thread's record, connected only by the stored pid.

## 6. When it fires (short version)

While a thread runs, the kernel periodically checks its timer tree. If the
leftmost expiry is due, `collect_timerqueue()` removes the node, marks it
`firing`, records `handling = current` (the task handling the expiry), and
puts it on a temporary list; `handle_posix_cpu_timers()` then processes each
entry (e.g. queues a signal). You don't need the details yet — just recognize
the function names, because the exploit deliberately makes these functions
run later.

## 7. The three cleanup paths

| path | entered from | object work | node work |
|---|---|---|---|
| `posix_cpu_timer_del()` | `timer_delete()`, `exit_itimers()` | free | look up task by stored pid → `disarm_timer()` → `cpu_timer_dequeue()` (uses `head`) |
| `cleanup_timerqueue()` | reap → `__exit_signal()` → `posix_cpu_timers_exit()` | none | `timerqueue_getnext()` + `timerqueue_del()` loop; sets `head = NULL` |

The first path *needs the pid lookup to succeed* to touch the tree. The
second path works directly on the thread's queue and doesn't look anything
up. The bug lives in the gap between them; chapter 7 walks it.

## Hands-on

1. `strace -e trace=timer_create,timer_settime,timer_delete ./tstrace` from
   chapter 1 — see `which_clock=3`. Change the clock to
   `CLOCK_PROCESS_CPUTIME_ID` and then `CLOCK_MONOTONIC`; watch the numbers
   change to 2 and 1.
2. Read `posix-cpu-timers.c`: `pid_for_clock` (57–100),
   `posix_cpu_timer_create` (386–414), `timer_base` (416–...), `arm_timer`
   (649–672).
3. `grep -n THREAD_CLOCK posix-cpu-timers.c` and confirm
   `thread_cpu_timer_create` rewrites `it_clock`.
4. Re-read `struct cpu_timer` in `include/linux/posix-timers.h` and write one
   sentence per field: `node`, `head`, `pid`, `elist`, `firing`, `nanosleep`,
   `handling`.
5. Answer out loud: for `CLOCK_PROCESS_CPUTIME_ID`, whose record holds the
   node? For `CLOCK_THREAD_CPUTIME_ID`?

## Checkpoint

1. Which structure owns the timer *object*? Which owns its *node*?
2. Why does the object store a `struct pid` instead of a `task_struct *`?
3. What is `head` for, who sets it, and when is it cleared?
4. What does `CPUCLOCK_WHICH` extract from the internal clock id, and what is
   the value for our timer?
5. In the cleanup table, which path can do nothing about the tree if a lookup
   fails, and which path never looks anything up?
