# The timer LPE, explained from zero

A slow, chapter-by-chapter walk through `InfinityCore/timer/CVE-2026-98260-ubuntu.c`
and the kernel machinery it abuses.

## Who this is for

You can read C and use a Linux shell. You do **not** need any prior kernel
experience. Nothing here assumes you know what an RCU, an RB tree, a PID type,
or a slab allocator is — those get built up one chapter at a time.

## The deal

- One chapter at a time. Each is short on purpose.
- Each chapter ends with **Hands-on** (commands/programs to run on this machine)
  and a **Checkpoint** (questions you should be able to answer).
- If a sentence doesn't land, quote it back to me and try to say what you think
  it means. That tells me exactly where the model in your head diverges.
- Do not read the summary notes at `notes/CVE-2026-98260-timer-walkthrough.md`
  until you're through chapter 12. That file is the "after" picture.

## The material

- The exploit: `InfinityCore/timer/CVE-2026-98260-ubuntu.c` (we start reading it
  around chapter 8).
- The kernel source we quote: `kernel-src/pre-fix/` — a copy of the relevant
  files from upstream at commit `d2710c8d938a` (the parent of the fix
  `acb03d388181`). Line numbers in the book refer to these files.
  `kernel-src/pre-fix/README.md` says where each file comes from.

## Reading order

Part A — the pieces (chapters 1–6). Build the mental model.
Part B — the bug and the exploit (chapters 7–12). Now the PoC makes sense.
Part C — extra machinery and next steps (chapters 13–14).

| # | Chapter | Status |
|---|---------|--------|
| 1 | Processes, threads, syscalls, PIDs — the userspace view | written |
| 2 | The kernel's view: `task_struct`, `signal_struct`, `struct pid`, `cred` | written |
| 3 | Timers: what `timer_create` really does, and where a CPU timer lives | written |
| 4 | The timerqueue: an RB tree with a cached leftmost node | written |
| 5 | `execve`: the world's most complicated syscall | written |
| 6 | Life cycles: who frees what, and when (`exit` vs *reap*, `kfree_rcu`) | written |
| 7 | Assembling the bug: the exact sequence | written |
| 8 | Reading the trigger in the PoC | coming |
| 9 | The transfer trick: `head == NULL` | coming |
| 10 | Leaking addresses: `handling` and `elist` | coming |
| 11 | The RB-tree write and the fake cred | coming |
| 12 | From fake cred to root shell | coming |
| 13 | Heap grooming: RCU, SLUB sheaves/barn, PCP, AIO pages | coming |
| 14 | Android porting, and how to hunt bugs like this | coming |

Suggested pace: two chapters a day. If a chapter feels dense, stop at the
checkpoint and ask before continuing.

## The whole story in five plain sentences (spoiler-free orientation)

1. A timer you create in userspace is a small kernel object, and the kernel
   also stores a little "when should this fire" tree node for it inside some
   thread's kernel record.
2. Normally, when you delete the timer or the thread dies, both the object and
   the tree node are cleaned up together.
3. There is a rare `execve()` situation where the kernel frees the object but
   forgets the tree node. That is a bug: the node points into memory that the
   kernel no longer owns.
4. If an attacker can get that memory reused as a page they control, the
   kernel will later walk the tree and write through the stale node — on data
   the attacker chose.
5. This exploit steers that write into the field that says "which user am I",
   and then uses the resulting privileges to get a root shell.

Everything between here and chapter 12 is filling in what each of those words
actually means, with the real code and with experiments you run yourself.
