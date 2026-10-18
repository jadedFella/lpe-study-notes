# Chapter 2 — The kernel's view: `task_struct`, `signal_struct`, `struct pid`, `cred`

Goal of this chapter: learn the four kernel objects the whole exploit revolves
around, and how to look them up in the real source. When you finish, you should
be able to explain "a per-thread CPU timer ties a timer object in one structure
to a tree node inside a thread's record, and finds the thread through a numeric
ID object that can fail to resolve."

## 1. `task_struct` — one thread

In the kernel, there is no "process object" separate from threads. Every
thread is a `struct task_struct` (defined in `include/linux/sched.h`, not
copied here — it's 2000+ lines; we'll quote fields as needed).

Fields we will care about, with rough meanings:

| field | meaning |
|---|---|
| `pid` | this thread's numeric TID |
| `tgid` | the thread group's numeric ID (process id) |
| `group_leader` | pointer to the leader's `task_struct` (is NULL/self for the leader) |
| `thread_pid` | pointer to the `struct pid` object for this thread |
| `signal` | pointer to the shared `signal_struct` |
| `posix_cputimers` | per-thread CPU timer bookkeeping (this is where our tree node lives) |
| `cred` | pointer to the effective identity (user, groups, capabilities) |
| `real_cred` | pointer to the "real" identity |
| `mm` | the address space (shared by threads) |

## 2. `signal_struct` — one process

Threads of one process share a `struct signal_struct`. It holds process-wide
things: the signal handlers/queue, the process CPU-time totals, and — important
for us — the list of that process's POSIX timers:

```
struct signal_struct {
    ...
    struct hlist_head   posix_timers;   /* all k_itimer objects of this process */
    ...
    atomic_t            live;           /* how many threads are still alive */
    ...
};
```

`live` is decremented when each thread exits. When it hits zero (`group_dead`),
some process-wide cleanup runs — chapter 6 will build on that.

## 3. `struct pid` — the kernel's phone book

Numbers are not identity; `struct pid` is. When you ask the kernel "who is
thread 1234?", it doesn't scan every `task_struct`; it looks up the `struct
pid` object for number 1234 and asks "which task is attached to you?".

A `struct pid` can be attached to different *kinds* of numbers at once — the
same object may represent a TID, a TGID, etc. `pid_task(pid, type)` retrieves
the task attached under a given type:

- `PIDTYPE_PID` — the thread with this TID (used for per-thread things),
- `PIDTYPE_TGID` — the leader of the thread group with this process id.

The lookup can return `NULL`: "this `struct pid` currently has no task
attached under this type". Hold that thought — this exact `NULL` is the hinge
of the entire vulnerability, and we'll see it again in chapter 7.

If you want to look at the real code: `kernel/pid.c` (in
`kernel-src/pre-fix/kernel/pid.c`). The functions are `attach_pid()`,
`detach_pid()`, and `pid_task()`.

## 4. `cred` — who am I allowed to be

Every task points to a `struct cred` (`kernel-src/pre-fix/include/linux/cred.h`):

- `uid`, `gid` — real user/group id,
- `euid`, `egid` — effective ids (what permission checks mostly use),
- `fsuid`, `fsgid` — the ids used for **filesystem** checks, and
- capability sets (`cap_permitted`, `cap_effective`, ...).

There are two pointers in `task_struct`:

- `real_cred`: who you really are — set at login/exec of a normal program;
- `cred`: the identity currently in effect — normally the same object, but
  `setuid` binaries and some kernel operations swap `cred` for another object.

This distinction is why the exploit can work by corrupting **one pointer**:
almost every permission check reads `current->cred`, and a forged cred object
is enough to pass those checks. The fact that `real_cred` is untouched is why
the exploit ends with a clever "make a setuid file, let a *different* process
exec it" step instead of just calling `setuid(0)`. (Chapter 12 in full.)

## 5. Putting the pieces together (before timers)

At this point you can already draw this userspace-to-kernel map:

```
program calls getpid()  ->  kernel reads current->tgid
program calls getppid() ->  kernel ...
program calls getuid()  ->  kernel reads current->cred->uid
```

and for a multi-threaded process:

```
task_struct A (leader, tid==tgid)  ─┐
task_struct B (tid 1001)            ├─ share one signal_struct
task_struct C (tid 1002)           ─┘
```

Each `task_struct` has its own `thread_pid` pointing to its own `struct pid`.

## 6. Where the timer will fit (preview)

A POSIX timer object (`struct k_itimer`) is allocated by `timer_create()` and
put on `signal_struct.posix_timers` (the process-wide list) **and**, if it is a
per-thread CPU timer, a "when does it fire" node is inserted into the
**calling thread's** `task_struct.posix_cputimers` tree.

The kernel later finds the owning thread by taking the `struct pid` stored in
the timer and calling `pid_task(pid, PIDTYPE_PID)`.

So the full chain for a per-thread CPU timer is:

```
struct k_itimer (object)
    ├── signal_struct.posix_timers list ....... process-wide ownership
    └── it.cpu.pid ──► struct pid ──► pid_task() ──► task_struct
                                                        └── posix_cputimers tree
                                                            (holds the timer's node)
```

If that `pid_task()` lookup returns `NULL` while the tree node still exists,
the kernel's cleanup code gets confused. That is the bug. Chapter 3 makes the
timer side precise; chapter 5 makes the `execve` side precise; chapter 7 puts
them together.

## Hands-on

### A. See the kernel's view through `/proc`

```
$ cat /proc/self/status | grep -E '^(Pid|Tgid|PPid|Uid|Gid):'
$ ls /proc/self/task
$ cat /proc/<some-thread-tid>/status | grep -E '^(Pid|Tgid):'
```

`Pid` is the TID, `Tgid` the process. The `Uid:` line has four numbers — real,
effective, saved, filesystem (in that order). That fourth one is `fsuid`, the
one file operations use.

### B. Read the real `cred` struct

Open `kernel-src/pre-fix/include/linux/cred.h` and find `struct cred`. Identify:
`usage`, `uid`, `gid`, `euid`, `egid`, `fsuid`, `fsgid`, and the capability
sets. Notice that `euid` and `fsuid` are separate fields.

### C. Find the timer-related fields in headers

```
$ grep -n "posix_timers" kernel-src/pre-fix/include/linux/posix-timers.h
$ sed -n '45,95p' kernel-src/pre-fix/include/linux/posix-timers.h
```

You are looking at `struct cpu_timer` — the part of a `k_itimer` that gets
queued. Read the comments for `node`, `head`, `pid`, `elist`, `firing`,
`handling`. Don't worry if the code around them isn't clear yet; chapter 3
walks through it.

## Checkpoint

1. Which kernel object represents a thread? Which represents a process?
   Which fields of `task_struct` point to them?
2. What does a `struct pid` store, and what are the two lookup types we care
   about (`PIDTYPE_PID` vs `PIDTYPE_TGID`)? What is the "attached task" of a
   `struct pid` for a given type?
3. What's the difference between `cred` and `real_cred`? Why does `fsuid`
   exist separately from `euid`?
4. Draw the chain from a `k_itimer` object to the thread that owns it. Why
   does that chain go through `struct pid` and not a direct pointer to the
   `task_struct`? (Think: threads die, but the timer object may outlive them
   briefly. The kernel's answer to "which task?" must handle "none right now")
5. What can `pid_task()` return, and what does `NULL` mean semantically?

When you can answer these, continue to chapter 3.
