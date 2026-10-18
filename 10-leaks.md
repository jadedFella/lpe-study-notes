# Chapter 10 — Leaks: the kernel writes our addresses for us

Goal of this chapter: follow `run_stage1()` (PoC 716–931) line by line. By the
end you should see how a thread that merely *runs* and then sits in a spinlock
leaks three kernel addresses into a page we own: its own `task_struct`, a
kernel stack pointer, and the direct-map address of the page — the alias that
makes everything in chapters 11–12 possible.

References: `collect_timerqueue()` (posix-cpu-timers.c:864),
`handle_posix_cpu_timers()` (1354–1457), PoC `prepare_aio_page()` (440–449),
`run_stage1()` (716–931), `prepare_stage2()` (605–716).

## 1. Two things we need before anything else

The dangling node lives at `object + 0xe0` inside a page we control (chapter 9).
To turn kernel-side writes into power, the exploit needs:

1. **A task pointer** for the worker that owns the tree. The final write
   (chapter 11) targets two fields inside `task_struct`:
   `task->cred` and the SCHED queue head `task->posix_cputimers.bases[...].tqhead`
   (PoC calls them `cred_slot = task + 0xd00` and `head = task + 0xca0`).
   These offsets are BTF-derived for the tested kernel (chapter 14 shows how to
   obtain them on your own).
2. **The kernel (direct-map) address of our page.** Userspace addresses and
   kernel virtual addresses for the same physical page differ by a fixed
   delta. All pointers the kernel will follow must be written as *kernel*
   addresses; all bytes we write come from the *user* mapping. One leak of any
   kernel pointer into the page gives the delta.

Both leaks are produced, for free, by the kernel's own timer-collection path.
The trick is to be *running a task that is in the middle of checking its CPU
timers* exactly when the node is due.

## 2. Laying the trap

After `delete_oracle_candidates()` the object is freed (RCU-pending). The
exploit now reclaims its slab page as userspace memory and fills it. PoC
`allocate_aio_spray()` (451) allocates 64000 anonymous pages plus 64000 AIO
ring pages, and runs `prepare_aio_page()` on every one (440):

```c
	memset(page, 0, 4096);
	for (size_t base = 0; base < 4096; base += 128) {
		*(uint64_t *)(page + base + 48) = 1;   /* +0x30 */
		*(uint32_t *)(page + base + 64) = 1;   /* +0x40 */
		*(uint64_t *)(page + base + 104) = 1;  /* +0x68 */
		*(uint64_t *)(page + base + 120) = 1;  /* +0x78 */
	}
```

Why every 128 bytes? Because the reclaiming page may end up under the object
at any 128-byte-aligned offset. Whatever the offset, the object's fields land
on one of those stamps:

| stamp (relative to a 128-byte block) | field it is meant to hit |
|---|---|
| `+0x30` | validity word: `it_signal` read by `posixtimer_valid()` |
| `+0x40` | `it_lock` — stamped `1` so the handler *spins* on it |
| `+0x68` | guard word consumed around collection/delete |
| `+0x78` | `node.expires` (`0xf8 mod 0x80 = 0x78`) − so a node is "due" |

Everything else in the page is zero, in particular:

- `node.expires` stamp = `1` → long overdue → the node is *always* collected;
- `it.cpu.head` (`+0x100`, block offset `+0x00`) = `0` → the dequeue in the
  collect path will be **skipped again** → the node stays in the queue;
- `firing` (`+0x120`), `handling` (`+0x128`) = 0;
- `elist` (`+0x110`) = 0.

(Chapter 13 covers the volumes, the page-allocator steering and why we get this
page back at all. For now: assume it worked and the dangling node now points
into an AIO/anon page full of this pattern.)

## 3. Phase 1: the worker runs, the kernel writes, we read

`run_stage1()` wakes workers in batches of `ORACLE_BATCH = 3` (738–746). The
seeded worker `w` spins in a userspace loop burning CPU (PoC 310–320,
`oracle_worker_main`), so its consumed CPU time — the quantity its CPU timer
measures — grows until it passes the cached next expiry (the candidate was
armed for 20 ms). Then its timer tick path runs `run_posix_cpu_timers()` →
`collect_timerqueue()` (posix-cpu-timers.c:864):

```c
	while ((next = timerqueue_getnext(head))) {
		ctmr = container_of(next, struct cpu_timer, node);
		expires = cpu_timer_getexpires(ctmr);
		if (++i == MAX_COLLECTED || now < expires)
			return expires;

		ctmr->firing = true;
		/* See posix_cpu_timer_wait_running() */
		rcu_assign_pointer(ctmr->handling, current);
		cpu_timer_dequeue(ctmr);
		list_add_tail(&ctmr->elist, firing);
	}
```

with `next` = our node, `expires` = our `1` bytes, `now` = the sampled CPU
clock. So, all writes into **our page**:

1. `ctmr->firing = true` → `+0x120 = 1`.
2. `ctmr->handling = current` → `+0x128 = task pointer` — **leak #1: the
   address of the worker's `task_struct`**.
3. `cpu_timer_dequeue(ctmr)`: `head` reads `0` → skipped. Node stays queued
   (this is what keeps the whole construction alive across multiple
   collections).
4. `list_add_tail(&ctmr->elist, firing)` → `elist.next = elist.prev = &firing`,
   the address of a local `LIST_HEAD(firing)` **on the worker's kernel stack**
   — a kernel stack pointer written into our page (leak #2a; see below).

Note the loop: because the node never leaves the queue, the `while` re-reads it
on every iteration, up to `MAX_COLLECTED = 20` times in one call. The repeat
`list_add_tail()` calls are rejected by the kernel's own list integrity check
as a "double add" (`__list_add_valid`), so the entry stays a clean
single-element list whose `next == prev == &firing`. This matters in §4.

Finally `handle_posix_cpu_timers()` (1354) processes the collected entry and
its very first act on the timer is `spin_lock(&timer->it_lock)` (1442). Our
stamp made `it_lock` equal `1` — the value for "locked" — so **the worker
spins inside the kernel, holding the timer hostage**, until we unlock it.
It cannot run any further userspace code; in particular it never sets its
`done` flag.

### The parent side

While this happens, the parent has a simpler job:

- The scan (748–777) walks every spray page looking for a kernel pointer in
  the object's `handling` slot. Since objects can start at any 128-aligned
  offset, the code checks offsets `0x28, 0xa8, 0x128, 0x1a8, ...`. Valid hits
  are `off == 0x28` (special case, §6) or `off >= 0x128`; then
  `object = page + off - 0x128`. The value found is `task` — **leak #1 in
  hands**. (The scan starts at offset 40 (`0x28`) and steps by 128: exactly the
  set of places a `handling` field can be.)
- It then waits until **exactly one** worker of the currently woken batch has
  not set `done` (803–824) — that worker is the one stuck on the fake
  `it_lock`. Call it `winner`. This is the same "oracle" idea as in chapter 8:
  the kernel's misbehaviour is visible as a thread that fails to finish.
- Then it reads the `elist` (element at `object + 0x110`) until
  `next == prev` and the value looks like a kernel pointer (826–835) →
  that value is `&firing`, the kernel stack address: **leak #2a captured as
  `stack_link`**.

## 4. Phase 2: let it finish, read the self-pointer

Now the parent re-schedules the timer into the future and releases the lock
(845–865), with careful ordering:

```c
	clock_gettime(oracle->workers[winner].clockid, &sample);   /* now */
	future = timespec_to_ns(&sample) + STAGE1_FUTURE_NS;       /* +250 ms */
	*(volatile uint64_t *)(object + 0xf8) = future;  /* node.expires */
	*(volatile unsigned char *)(object + 0x120) = 0; /* firing = false */
	...
	*(volatile unsigned char *)(object + 0x40) = 0;  /* it_lock -> unlocked */
```

Order matters. `expires` must be pushed into the future *before* the worker
resumes, or its next collection would immediately re-collect the node at
`expires = 1` and the dance would repeat. `firing = 0` tells the handler "this
timer raced with a rearm/delete — do not deliver an event" (1451: `if (likely
(cpu_firing)) cpu_timer_fire(timer);`). And only then is the lock cleared.

The worker wakes up inside `handle_posix_cpu_timers()` and runs (1442–1455):

```c
		spin_lock(&timer->it_lock);           /* now succeeds */
		list_del_init(&timer->it.cpu.elist);
		cpu_firing = timer->it.cpu.firing;    /* false (we cleared it) */
		timer->it.cpu.firing = false;
		if (likely(cpu_firing))
			cpu_timer_fire(timer);        /* skipped */
		rcu_assign_pointer(timer->it.cpu.handling, NULL);
		spin_unlock(&timer->it_lock);
```

`list_del_init()` is the third gift: it makes `elist.next = elist.prev =
&elist` — and `elist` lives *inside our page*, so the kernel writes **the
direct-map address of `object + 0x110`** into our page. The parent is already
polling for it (867–877): a second, different value with `next == prev` →
`direct_elist`. Hence (883):

```c
	kernel_object = direct_elist - 0x110;
```

with a sanity check that `kernel_object` and our user `object` share the same
page offset (884–892). Now the alias is known:

```
user byte at  (uintptr_t)object   == kernel byte at kernel_object
alias_delta = kernel_object - (uintptr_t)object
```

Every further kernel address the exploit needs inside this page is
`user_addr + alias_delta` (see `prepare_stage2`, 617: `alias_delta =
kernel_anchor - (uint64_t)(uintptr_t)user_anchor`).

After that the worker returns to userspace, sees `stage1_seen`, sets `done`
(894–904), and politely waits for stage 2. The exploit has:

| leak | value | used for |
|---|---|---|
| #1 `handling` | `task_struct *` of worker `w` | `task + 0xd00` = `&task->cred`; `task + 0xca0` = its SCHED `tqhead` |
| #2a `elist` (from stack) | kernel stack address | phase distinction for #2b (see below) |
| #2b `elist` (self) | direct-map address of `object + 0x110` | `kernel_object` → `alias_delta` |

## 5. Why the kernel leaks at all

None of this is an accident of the exploit. It is the kernel *design*:

- `collect_timerqueue()` records `handling = current` so that a concurrent
  timer delete can wait for the process that is currently handling the timer
  (`posix_cpu_timer_wait_running()`). It is a synchronization pointer stored in
  the timer object — and the timer object is what we own.
- The `firing` list is local to the handler's stack; `list_add_tail()` /
  `list_del_init()` leave their list-head addresses in the timer's `elist`,
  which is also part of the object.

Both pieces of bookkeeping are legitimate and correct — for a timer whose
object is alive. The bug (chapters 6–7) is that a *freed* object is still
reachable from a live queue, so the bookkeeping writes land in attacker-owned
memory.

## 6. The cross-page variant

The AIO user mapping and the kernel's allocation of the object need not share
the same 4 KiB page alignment: the object can start 0x100 bytes before the end
of one user-mapped page, so its last `0x80` bytes (including `head`, `elist`,
`firing`, `handling`) live in the *next* user page. The scan catches this when
the kernel pointer appears at offset `0x28` of a page: then the object begins
at `marker_page - 0x100` (the previous page). The exploit cannot address
`object` and `object + 0x100` with one pointer, so it:

- keeps `marker_page` and uses broadcasts (`broadcast_u64/u8`, PoC 584–604) to
  stamp *all* pages at the tail offsets: `0xf30 → object+0x30`,
  `0xf40 → object+0x40`, `0xf68 → object+0x68`, `0xfe0/0xfe8/0xff0/0xff8 →
  object+0xe0/e8/f0/f8` (any page can be the "previous page" of some object);
- treats `user_anchor = marker_page`, `kernel_anchor = kernel_object + 0x100`
  for the alias computation (614–617) — the two addresses that describe the
  same physical byte.

Everything else is identical; check the two branches against each other and
convince yourself they compute the same quantities.

## Hands-on

1. Read PoC `prepare_aio_page` (440–449) and `run_stage1` (716–931). For each
   of these page offsets, say which object field it hits and who writes/reads
   it: `0xf8`, `0x100`, `0x110`, `0x120`, `0x128`, `0x40`, `0x30`.
2. Read `collect_timerqueue` (posix-cpu-timers.c:864–888) and
   `handle_posix_cpu_timers` (1354–1457). Mark every store to a `cpu_timer`
   field; for each, say which leak (if any) it produces.
3. Work the scan arithmetic on paper:
   - handling found at `page + 0x1a8` → where is `object`? Where is `elist`?
   - handling found at `page + 0x28` → where are `object`, `elist`, and which
     page is `marker_page`?
4. Answer: why must `node.expires` be set to `future` *before* `it_lock` is
   unlocked, and what specifically would go wrong in the other order?
5. Answer: the worker reads its own `done` flag into userspace after phase 2.
   Suppose the unlock in phase 2 did not happen (typo: `0x48` instead of
   `0x40`). Which of the three leaks would you still get, and which would you
   lose? (Hint: which write happens before vs. after the lock is taken.)
6. Extra: explain in your own words why `list_add_tail` repeats are harmless
   here, and what the `MAX_COLLECTED` cap (862) is for.

## Checkpoint

1. List the three kernel addresses leaked into the page, the offset each lands
   at, and the exact kernel line that writes it.
2. What does `alias_delta` mean, and why is it needed for every pointer the
   exploit will write in chapter 11?
3. Which two fields does the parent write to release the stuck handler, and in
   what order? Why that order?
4. Why is "exactly one worker not done" a reliable oracle for the seeded
   worker?
5. In the cross-page case, why are writes done via *broadcast* to all pages at
   offsets like `0xf30`/`0xff8` instead of directly at `object + 0x30`?
