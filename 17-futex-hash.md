# Chapter 17 — The futex hash UAF: a refcount that counts someone else, and the pipe flag that rewrites `/usr/bin/passwd` (CVE-2026-80775)

Goal of this chapter: two new worlds in one bug. First, **futexes** — the
kernel objects behind every mutex and `pthread_cond` — and how their private
hash table is reference-counted per `mm`. Second, the most reusable
*endgame* in the whole `InfinityCore` set: turning a UAF into a flag flip that
lets an ordinary pipe write **into the page cache of a setuid binary**. (If
you have heard of the Dirty Pipe vulnerability from 2022: this exploit
reconstructs exactly that primitive, only the flag flip comes from a futex
bug.)

Material: `InfinityCore/futex/README.md` and
`InfinityCore/futex/CVE-2026-80775-ubuntu.c`. Target: Ubuntu 26.04,
`7.0.0-30-generic`. Introduced by `d9b05321e21e`, fixed by `bde023808364`.

## 1. Background: private futex hashes and what protects them

A futex ("fast userspace mutex") is a 4-byte user word the kernel only gets
involved with when the fast path fails: you `FUTEX_WAIT` when the word says
"locked". The kernel needs, per waiting thread, a **queue entry** (`futex_q`)
and, per futex address, a **hash bucket** (`struct futex_hash_bucket`) holding
the waiter chain and a spinlock.

For private futexes (used by almost all `pthread` primitives), the kernel keeps
a **hash table per `mm_struct`** — the *private futex hash*, `fph` — and it
can be resized at runtime:
`prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS, slots, ...)`.

Resizing a live hash is a lifetime problem: threads may be inside the current
table right now. The scheme (as the vulnerable source shows):

- each hash has a state, `FR_PERCPU` (the normal state) or dead/atomic;
- references are counted in the **`mm`**: a per-CPU counter set
  (`mm->futex_ref`) plus an `atomic_long` fallback;
- a futex operation grabs a reference inside an RCU section, then receives a
  bucket pointer and uses it **outside** the RCU section;
- to swap in a new table, the kernel folds the per-CPU counters into the
  atomic counter, waits for the total to hit zero, moves waiters, publishes
  the new table, and `kvfree_rcu()`s the old one.

Here is the subtle design decision that becomes the bug: the counters live in
the `mm`, **not in the hash**. Get and put both read the *current*
`mm->futex_ref`, whatever hash they belong to:

```c
if (READ_ONCE(fph->state) == FR_PERCPU) {
    __this_cpu_inc(*mm->futex_ref);      /* get */
    ...
    __this_cpu_dec(*mm->futex_ref);      /* put */
}
```

Also in play: **PI futexes** (`FUTEX_LOCK_PI`, used by priority-inheritance
mutexes). A waiter's `futex_q` stores `q->lock_ptr = &hb->lock` while queued.
If the waiter is interrupted by a signal, the cleanup path walks that pointer —
we will reuse it as a stale door into freed memory.

## 2. The bug

Default hash allocation gives every sibling sharing the `mm` a hash *up
front* — except `vfork`:

```c
return (clone_flags & (CLONE_VM | CLONE_VFORK)) == CLONE_VM;
```

The justification: after vfork the parent is suspended until the child exits
or execs, so parent and child are never *concurrently* in the same `mm` — and
"first thread allocates, no locking needed". But that invariant is breakable:

1. parent `clone3(CLONE_VM | CLONE_VFORK)` → **intermediate** child (parent
   suspended);
2. intermediate `clone3(CLONE_VM | CLONE_VFORK)` → **grandchild**;
3. grandchild `kill(intermediate, SIGKILL)` → the intermediate child dies, so
   the *outer* vfork completes and **the parent runs again** — while the
   grandchild is still alive, both sharing the same `mm`, with **no default
   hash allocated**.

Both then call `PR_FUTEX_HASH_SET_SLOTS` for the first time, and the
"no locking needed" assumption fails:

```c
if (!mm->futex_ref) {
    mm->futex_ref = alloc_percpu(unsigned int);   /* both see NULL */
    if (!mm->futex_ref)
        return -ENOMEM;
    this_cpu_inc(*mm->futex_ref); /* 0 -> 1 */
}
```

Two different counters are allocated; the later store wins the pointer field
and the loser's reference is unreachable forever. When the kernel later folds
the surviving counter into the atomic value, the total is short. In the PoC's
sequence the active old hash's atomic reference lands at **`-1`**.

Now the fatal detail: the atomic path does

```c
return atomic_long_inc_not_zero(&mm->futex_atomic);
```

`-1` is not zero — so "take a reference" *succeeds* and turns the count into
**0**, which is also the encoding of "no references / dead". One caller
believes it holds a bucket of the old hash; another caller (the pivot path
`__futex_pivot_hash()`) sees 0, declares the old hash dead, and
`kvfree_rcu()`s it. The queued `futex_q` still stores `q->lock_ptr` into that
freed memory.

The fix is a one-pattern lesson in publish-then-free: allocate into a local,
take the initial reference *before* publishing, and let `cmpxchg()` pick a
single winner; the loser frees its own counter:

```c
unsigned int __percpu *ref = alloc_percpu(unsigned int);
if (!ref)
    return -ENOMEM;
this_cpu_inc(*ref);                        /* 0 -> 1 before publish */
if (cmpxchg(&mm->futex.phash.ref, NULL, ref))
    free_percpu(ref);
```

## 3. The exploit

### 3.1 Stages 1–2: create `-1`, park a PI waiter in the old hash

- The nested-vfork dance above; parent asks for 8 slots, grandchild for
  262,144. Timing is critical, so the PoC gates execution with slow syscalls:
  up to 60,000 `io_setup()` contexts, and a robust-list cleanup with 2,048
  nodes to control the get/put ordering.
- A **target** thread waits on a PI futex that the **controller** owns. At the
  moment a lookup turns the old hash's count from `-1` to `0`, a **selector**
  thread looks up a different private futex, sees "dead", and publishes the
  new 262,144-slot table.
- The PoC verifies the state before proceeding: the controller trying to lock
  the PI futex the target owns gets `-EDEADLK`, waking the old owner address
  in the *new* hash returns 0, and the target has not returned. That means
  exactly one thing: the target still sits in a bucket of the old hash with a
  stale `q->lock_ptr`.

### 3.2 Stage 3: geometry — hitting `pipe_buffer[1].flags` with `waiters`

Reclaim target: the old hash is `kmalloc-cg-1k` material:

```
8 slots:  64 (header) + 8 × 64 (buckets) = 576 bytes
waiters  in queues[0]                     = object offset 64
pipe ring, 16 entries: 16 × 40 = 640 bytes   (also kmalloc-cg-1k)
pipe_buffer.flags                         = entry offset + 24
=> pipe_buffer[1].flags                   = 40 + 24 = 64
```

Two different objects of the same cache size, with `waiters` and `flags`
landing on the same byte. That is not luck — it is chosen.

- Fill the RCU free path: create 11 dummy `mm`s on the same CPU, each
  upgrading an 8-slot hash to 16 slots, so 12 objects (the target + 11) flush
  the free sheaf and actually reach the allocator.
- Spray: 4 workers × 16 pipes × 15 waves = 960 pipes. Each pipe's ring is
  shrunk to 8,192 bytes and grown back to 65,536, so
  `pipe_resize_ring()` `kzalloc`s a fresh 16-entry ring (zeroed). The stale
  target hash gets replaced by one of these rings.
- Prime the buffers: `splice()` transfers **one byte from immediately before
  the ELF entry** of `/usr/bin/passwd` into each pipe. Now
  `pipe_buffer[1]` references the **page cache page of the executable**, and
  the pipe's next write position is exactly the ELF entry point.

### 3.3 Stage 4: the decrement that becomes a flag

The PoC sends `SIGKILL` to the target through a pidfd. The interrupted PI
futex path does cleanup, which walks the stale `q->lock_ptr`:

```c
void __futex_unqueue(struct futex_q *q)
{
    ...
    hb = container_of(q->lock_ptr, struct futex_hash_bucket, lock);
    plist_del(&q->list, &hb->chain);
    futex_hb_waiters_dec(hb);        /* decrements 32-bit ->hb->waiters */
}
```

`waiters` is 32 bits. Overlaid on `pipe_buffer[1].flags`, the decrement takes
the fresh ring's `flags = 0` to `0xFFFFFFFF` — which includes
`PIPE_BUF_FLAG_CAN_MERGE` (bit `0x10`). The normal pipe write path then does
what it always does for that flag:

```c
if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) &&
    offset + chars <= PAGE_SIZE) {
        ret = copy_page_from_iter(buf->page, offset, chars, from);
```

and copies attacker data straight into the referenced page — the **page cache
page of the setuid `/usr/bin/passwd`**. (This is Dirty Pipe's recipe, built
from scratch: normally `splice()` from a file clears the flag; here the flag
is forged by kernel arithmetic.)

Safeguards the PoC adds, all worth copying:

1. write 16 bytes to **every** pipe and verify SHA-256 of the whole file
   against the expected intermediate state — identify the winning pipe;
2. write the remaining 100 bytes of the 116-byte stub; verify the full hash;
3. patch starts before the ELF entry, so the stub runs *before* the real
   program.

The stub does `setresgid(0,0,0)` + `setresuid(0,0,0)`, then `execveat()`s the
PoC itself from a reserved file descriptor (198) — full root.

### 3.4 Stage 5: clean up after yourself

- Before the rest of the tree sets `no_new_privs`, the PoC has already forked
  the payload child (so **it** keeps `no_new_privs = 0` and can gain
  privilege from the setuid bit; the parent sets it to reduce its own attack
  surface).
- The root incarnation verifies the patched file hash, then **restores the
  original 116 bytes** of `/usr/bin/passwd` and verifies the original hash.
  Executing from the already-open FD used `AT_EMPTY_PATH`, so no path-based
  race can swap the file mid-exec.
- Then `/bin/bash`, with the caller's standard streams intact.

## 4. What this chapter adds to your toolbox

| technique | why it generalizes |
|---|---|
| refcount not tied to its object | get/put via `mm->current_pointer` means a swapped pointer silently re-assigns references; check *what* a reference is a reference *to* |
| fold/aggregate arithmetic | summing per-CPU counters has signedness and saturation edge cases; `-1` in an `inc_not_zero` refcount is a classic |
| breaking "can't run concurrently" assumptions | vfork assumed quiescence; a third party (SIGKILL) re-activated the parent. Review every optimization justified by "X cannot happen concurrently" |
| overlaid geometry | two same-cache objects whose interesting fields share an offset: `waiters` ↔ `flags` at +64. Compute these early; they pick your primitive |
| decrement → boolean flag | a 32-bit decrement of 0 gives a value that *contains* the bit you need (`CAN_MERGE`) — arithmetic corruptions are not just numbers, they are bitmaps |
| page-cache overwrite | writable page cache = rewriting a read-only-on-disk executable; verify with hashes, restore afterwards, exec by FD |
| `no_new_privs` and setuid | setuid transitions require `nnp == 0`; plan which process keeps it |

## Hands-on

1. Read `InfinityCore/futex/README.md` §"Root Cause" and §"Exploit". Mark each
   numbered callout `[1]`–`[11]` and match it to a sentence above.
2. The fixed publication race, in this tree:

   ```sh
   grep -n "cmpxchg(&mm->futex" /home/hp/lpe-study/linux/kernel/futex/core.c
   sed -n '1860,1885p' /home/hp/lpe-study/linux/kernel/futex/core.c
   ```

   Also see the fold function around lines 1640–1665 (`per_cpu_ptr(...)`) —
   the loop that adds up per-CPU counters is where the missing reference
   *would* have mattered.
3. See the flag that does the damage:

   ```sh
   grep -n "CAN_MERGE" /home/hp/lpe-study/linux/include/linux/pipe_fs_i.h /home/hp/lpe-study/linux/fs/pipe.c
   ```

   Note where normal kernels *set* it (`fs/pipe.c:615`: only anonymous pipe
   buffers) versus where it is *checked* (`fs/pipe.c:558`). The exploit sets
   it on a buffer pointing at a file page — the one combination the flag was
   never meant to see.

4. Find the decrement path:

   ```sh
   grep -n "futex_hb_waiters_dec" /home/hp/lpe-study/linux/kernel/futex/core.c
   ```

   Read around lines 815–850 and identify which caller runs from the
   signal-interrupted PI futex cleanup.

5. In the PoC, confirm the nested-vfork trick and the pipe sizing:

   ```sh
   grep -n "CLONE_VFORK_LOCAL\|SIGKILL_X86_64" /home/hp/lpe-study/InfinityCore/futex/CVE-2026-80775-ubuntu.c | head
   grep -n "8192\|65536" /home/hp/lpe-study/InfinityCore/futex/CVE-2026-80775-ubuntu.c | head
   ```

6. Reading homework: `man 2 vfork` (find the sentence about the parent being
   suspended — the assumption this bug breaks) and `man 2 splice`.

## Checkpoint

1. Why are references to a private futex hash counted in the `mm` and not in
   the hash itself, and why does that break here?
2. Walk through what the grandchild's `SIGKILL` changes about the vfork
   guarantee, and why the kernel's "no locking needed" comment was wrong.
3. What does a count of `-1` mean to `atomic_long_inc_not_zero()`, and what
   value results ("successfully")? Why is that value special to the pivot
   path?
4. Explain the aliasing arithmetic: why does `queues[0].waiters` share an
   address with `pipe_buffer[1].flags`, and why must both objects be in the
   same kmalloc cache?
5. Why does the exploit splice the byte *just before* the ELF entry instead
   of the first byte?
6. What three things does the PoC verify with SHA-256, and why does it bother
   to restore the original bytes of `/usr/bin/passwd`?
