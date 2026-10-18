# Chapter 1 — Processes, threads, syscalls, PIDs: the userspace view

Goal of this chapter: be able to say precisely what a "process", a "thread",
a "PID", a "TID", a "leader thread", and a "syscall" are — because the whole
bug is about *which thread* a timer belongs to and what `execve()` does to
thread identities.

## 1. Program vs process

A **program** is a file on disk (`/bin/bash`). A **process** is what you get
when the kernel loads that file into memory and starts executing it: an
instance with its own address space (its private view of memory), its own open
files, its own identity (user, permissions).

The same program can be several processes at once: open three terminals, you
have three independent `bash` processes.

## 2. Threads: one process, several flows of execution

A process can contain several **threads**. Every thread has its own CPU
registers and stack — it runs independently — but threads of one process
*share* the address space and open files.

In userspace:

- `getpid()` returns the process id (the same value for all threads).
- `gettid()` returns the thread id (different for each thread).

On Linux, a thread id *is* a pid: the kernel really only knows threads; a
"process" is just a group of threads. That's why the fields are called TGID
(thread group id) and PID (thread id) in `/proc`:

```
$ cat /proc/self/status | grep -E '^(Pid|Tgid|PPid):'
Pid:    12345
Tgid:   12345
```

`Pid` = this thread's id (TID). `Tgid` = the process id. In a single-threaded
program they are equal.

### The leader thread

When a process is created, its first thread is special: it is the **thread
group leader**, and its thread id *is* the process id (TGID). Every other
thread has a different TID but the same TGID.

```
$ ps -eLf | head -5
UID   PID   PPID   LWP  NLWP CMD
...   1000  1000   1000    4 bash
...   1000  1000   1001    4 bash   <- same process (PID 1000), different thread (LWP 1001)
```

`PID` column = TGID, `LWP` column = TID. Keep this table in mind; chapter 5 is
entirely about what happens when a *non-leader* thread calls `execve()`.

## 3. Syscalls: asking the kernel to do something

Your program can't touch hardware, allocate kernel memory, or set timers
directly. It asks the kernel via a **system call** (syscall). Under the hood a
syscall is:

1. put the request number and arguments in registers,
2. execute a special CPU instruction (on x86-64: `syscall`),
3. the CPU jumps into the kernel, which looks up the request in a table and
   runs the corresponding kernel function,
4. the kernel returns a result, and the CPU returns to your program.

That's it. When you call `timer_create()` in C, glibc does steps 1–2 for you;
the kernel side is a function called `do_timer_create()` in
`kernel/time/posix-timers.c`. We will read that function for real in chapter 3.

`strace` prints every syscall a program makes. This is one of the best study
tools you have, and we'll use it a lot:

```
$ strace -e trace=timer_create,timer_settime,timer_delete ./your_program
```

## 4. `execve()`: replace the program, keep the process

`execve("/bin/ls", ...)` does something weird: it *replaces the running
program* with another one, in the same process. The PID does not change; open
files stay open (unless marked close-on-exec); the address space is thrown away
and rebuilt from the new program.

Later, the PoC will call `execve("/proc/self/exe", ...)`, which means "replace
me with a fresh copy of myself". Understanding why that's useful requires
chapter 5, but remember the key fact now: **`execve()` doesn't create a
process; it transforms the calling thread's process in place.**

## 5. Why we care (a first, vague whiff of the bug)

A POSIX timer created with `CLOCK_THREAD_CPUTIME_ID` measures the CPU time of
*the calling thread*. The kernel must therefore remember **which thread** the
timer belongs to, and when that thread exits or execs, the timer must be
cleaned up correctly.

Chapter 2 will show you the kernel-side records; chapter 3 will show where the
timer's "when to fire" node is stored. The bug lives in the interaction of
those two things with `execve()` from a non-leader thread.

## Hands-on

### A. See your own threads

Save as `threads.c`:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

static pid_t tid(void) { return (pid_t)syscall(SYS_gettid); }

static void *worker(void *arg) {
    printf("worker: pid=%d tid=%d\n", getpid(), tid());
    sleep(30);
    return NULL;
}

int main(void) {
    printf("main:   pid=%d tid=%d\n", getpid(), tid());
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    return 0;
}
```

```
$ gcc -pthread threads.c -o threads && ./threads &
$ ps -eLf | grep threads     # note PID vs LWP
$ ls /proc/<PID>/task        # one directory per thread
$ cat /proc/<PID>/status | grep -E '^(Pid|Tgid):'
```

You should see: two TIDs (`task` has two entries), one TGID, and the TGID
equals the leader's TID.

### B. Watch a syscall happen

Save as `tstrace.c`:

```c
#include <time.h>
#include <signal.h>
#include <stdio.h>
int main(void) {
    timer_t t;
    struct sigevent sev = { .sigev_notify = SIGEV_NONE };
    struct itimerspec its = { .it_value = { .tv_sec = 60 } };
    timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &t);
    timer_settime(t, 0, &its, NULL);
    printf("armed\n");
    sleep(2);
    timer_delete(t);
    return 0;
}
```

```
$ gcc tstrace.c -o tstrace
$ strace -e trace=timer_create,timer_settime,timer_delete ./tstrace
```

You'll see the three syscalls and their arguments. Note `CLOCK_THREAD_CPUTIME_ID`
appears as a number (`3` on x86-64). We will meet that number again.

## Checkpoint

Try to answer in your own words, out loud or in a file:

1. What's the difference between a PID and a TID? Which one does `gettid()`
   return? Which one is the TGID?
2. In `ps -eLf`, which columns correspond to TGID and TID?
3. What does a syscall actually transfer between your program and the kernel?
4. What does `execve()` do to (a) the process identity, (b) the program, (c) the
   threads? (Hint: `execve` from a multi-threaded process destroys the other
   threads — we'll dig into *how* in chapter 5. For now, note the fact.)
5. Why would a timer need to know a *thread id* rather than just a process id?

When you can answer these, continue to chapter 2.
