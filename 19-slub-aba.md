# Chapter 19 — Racing the allocator itself: SLUB partial-list ABA (CVE-2026-97941)

Goal of this final chapter: close the circle. Chapter 13 taught you the
allocator as an *accomplice* — sheaves, barns, PCP lists you exploit. This
chapter races the allocator as the *victim*: a lock-free optimization inside
SLUB assumes that "the slab's freelist and counters look the same" means
"nothing else changed". Another CPU makes them look the same again by cycling
the slab through full → partial → full, and the assumption breaks. The result
here is only a kernel panic — and the writeup is honest about that: this PoC
demonstrates the corruption and the crash, not an LPE chain. Understanding
*why* it stops at a panic is as instructive as the other five exploits.

Material: `InfinityCore/slab/README.md` and
`InfinityCore/slab/CVE-2026-97941-arch.c`. Target: Arch Linux `7.2.4-arch1-2`.
Introduced by `ba7425312607`, fixed by `4a724bcf5d70`.

## 1. Background (mostly chapter 13, one level deeper)

SLUB manages same-sized objects in `struct slab`s:

- `slab->freelist` links the *free objects*; `inuse` counts used ones;
  `freelist == NULL` means the slab is **full**;
- each NUMA node keeps **partial** slabs (those with free objects) on
  `n->partial`, linked through `struct slab.slab_list`, protected by
  `n->list_lock`;
- the 7.2 per-CPU **sheaf** batches allocations. When it needs objects, the
  refill path `get_partial_node_bulk()` takes `n->list_lock`, moves some
  partial slabs onto a *private* list `pc.slabs`, drops the lock, then detaches
  each slab's freelist and fills the sheaf. Any objects left over are
  optimistically returned:

```c
if (__slab_try_return_freelist(s, slab, head, count)) {
    list_add(&slab->slab_list, &pc.slabs);      // back to the PRIVATE list
    break;
}
```

And the optimism lives in a cmpxchg that checks only *values*:

```c
old.freelist = slab->freelist;      /* detached -> NULL */
old.counters = slab->counters;
...
new.freelist = head;                /* our leftover objects */
new.inuse   -= cnt;
if (!slab_update_freelist(s, slab, &old, &new, ...))   /* {freelist,counters} */
    return false;
return true;
```

## 2. The bug: two locks, one object

The `cmpxchg` above is a statement about *the slab's numeric state*. But the
slab also has a *membership*: which list is `slab_list` linked into? That is a
different piece of state, guarded by a different lock (`n->list_lock`), and the
optimistic return does not hold it.

Interleaving that breaks it (two CPUs, one slab):

1. **Refill CPU** detached the slab's freelist and holds leftover objects. In
   its view the slab is "just emptied, off any list".
2. **Other CPU** frees one object into this full slab
   (`__slab_free()`): `was_full` is true, so under `n->list_lock` it does
   `add_partial(n, slab, ADD_TO_TAIL)` — the slab's `slab_list` is now linked
   into `n->partial`.
3. **Third actor (allocation CPU)** takes that object back out of
   `n->partial` via `get_from_partial_node()`; the last-object check calls
   `remove_partial()` → `list_del(&slab->slab_list)`.
4. If step 3's removal happens *immediately after* the object is taken, the
   **refill CPU's cmpxchg** still sees `{freelist = NULL, counters = ...}`
   — identical to what it saved in step 1, because the free+alloc round trip
   restored the values (this is the **ABA** pattern). It succeeds, and
   `list_add(&slab->slab_list, &pc.slabs)` overwrites the slab's list links
   with links into the *private* list.
5. Now `remove_partial()`'s `list_del()` operates on **overwritten links**:
   it unlinks the entry from the private list (not from `n->partial`, which is
   what it believes), and writes `LIST_POISON` values into `slab_list`.
   `n->partial` still has neighbors pointing at this slab — a stale entry.
6. The next allocation walks `n->partial`, reaches the stale entry, and
   `remove_partial()` dereferences the poison pointers →
   **general protection fault → kernel panic** (`get_from_partial_node()`).

The fix (`4a724bcf5d70`) removes the cross-lock optimism: in
`__slab_try_return_freelist()`, take `n->list_lock`, do the cmpxchg **and**
`add_partial()` inside the same critical section, and stop linking into
`pc.slabs` afterwards. Membership and values can no longer disagree.

## 3. Triggering the race

The bug needs two CPU-local properties that a normal heap spray cannot give:
the target slab must be on a **remote NUMA node** (so frees take `__slab_free`,
not the local sheaf), and the allocation must take the **node slow path**. The
PoC constructs exactly that environment:

- four vCPUs with `slab_strict_numa` on the command line; CPUs 0/2 on node 0,
  CPU 1 on node 1;
- allocation worker (CPU 2) uses `set_mempolicy(MPOL_BIND, node1)`, so its
  local sheaf never matches and every allocation walks the node partial list;
- CPU 0 frees node-1 objects remotely.

The objects: SysV messages. A 900-byte payload plus the `struct msg_msg`
header lands in the `msg_msg-1k` cache (sheaf capacity 12), and every
`msgsnd`/`msgrcv` is a controllable allocate/free of one object.

Per-trial choreography (all times from a shared reference, 20,004 trials):

- **refill thread** (CPU 1, `SCHED_IDLE`): loops `msgsnd()` in batches of 12 —
  the batch that must interrupt mid-way;
- **free worker** (CPU 0): 8 µs after reference, `msgrcv()` frees a known
  message from a known full slab → step 2 (partial insertion);
- **allocation worker** (CPU 2): waits until the free is published (25 µs),
  then waits `1901 TSC cycles`, then `msgsnd()`s one message → the
  last-object removal (step 3);
- **preemption worker** (CPU 1, normal policy): wakes at a chosen time and
  preempts the `SCHED_IDLE` refill thread, spinning until the allocation gate
  is published, then sleeps on a futex — releasing CPU 1 so the refill thread
  resumes exactly as the critical allocation begins;
- **timerfd** jitters the wakeup offsets between 1,000 and 6,000 ns per trial,
  waking the pair up at shifting points inside the window.

After the critical allocation, CPU 2 sends **four more messages** from the
same cache: these walk the corrupted `n->partial` and hit the poison
dereference; dmesg shows the GPF inside `get_from_partial_node()`, and the
kernel panics.

## 4. Why this one stops at a panic

`list_del()` trusts the links it is given. On the next traversal, the entry
selected from `n->partial` has `slab_list` fields overwritten with poison by
the earlier removal, and the next `list_del()` reads those fields and uses
them as addresses — the fault happens before any attacker-useful write. To
turn this into LPE, an attacker would need, roughly:

- a way to make the stale traversal *not* dereference poison (different
  interleaving where links still point somewhere useful), or
- to win the window with a different consumer than `remove_partial()` — the
  corrupted `slab_list` needs to be consumed by an operation that writes to a
  controllable target before validating membership.

Those may exist; the writeup simply reports what was demonstrated:
unprivileged list corruption + reliable panic. In the exploit-development
mindset of chapter 14, this is the "crash, not primitive" stage —
categorizing it correctly is a skill, not a failure: DoS on a shared box is
already impact, and the trigger itself documents a correctness bug in one of
the kernel's most load-bearing algorithms.

## 5. What this chapter adds to your toolbox

| technique | why it generalizes |
|---|---|
| ABA on `cmpxchg` | equal values ≠ equal state. Optimistic concurrency needs a version tag, a wider state word, or another invariant — otherwise any free/alloc cycle can replay the "before" picture |
| two lock domains | value state (`{freelist, counters}`) and membership state (`slab_list`, `n->partial`) were guarded differently; the fix merged the critical sections |
| hardening as observability | `LIST_POISON` converts silent corruption into a loud fault. When planning exploitation, ask *which validation fires first* |
| race anatomy | preemption control (`SCHED_IDLE` victim + normal-priority interrupter), CPU-published gates, TSC spins, `timerfd` jitter, tens of thousands of trials — this is what "winning a narrow race" looks like in practice |
| environment as target property | NUMA binding + `slab_strict_numa` + per-CPU pinning were *required preconditions*, not optimizations |

## Hands-on

1. Read `InfinityCore/slab/README.md` §"Root Cause" and §"Triggering", and
   sketch the full interleaving on paper: which CPU holds which lock, and
   where exactly the cmpxchg succeeds "incorrectly".
2. Confirm the shape of the fix in the local tree:

   ```sh
   grep -n "__slab_try_return_freelist\|__refill_objects_node\|get_partial_node_bulk" \
       /home/hp/lpe-study/linux/mm/slub.c
   sed -n '5683,5715p' /home/hp/lpe-study/linux/mm/slub.c
   ```

   Find the `spin_lock_irqsave(&n->list_lock, ...)`, the `slab_update_freelist`
   inside it, and `add_partial(n, slab, ADD_TO_TAIL)` — then note that
   `__refill_objects_node` (line ~7309) calls it *without* re-linking into
   `pc.slabs`.
3. Check the environment prerequisite on your machine:

   ```sh
   cat /proc/cmdline
   numactl --hardware 2>/dev/null || lscpu | grep -i numa
   cat /sys/devices/system/node/online 2>/dev/null
   ```

   `slab_strict_numa` is an early kernel parameter (`mm/slub.c:8282`); a
   single-NUMA-node VM cannot host this trigger as written.
4. Look at the race anatomy in the PoC (no need to read the full file):

   ```sh
   grep -n "MESSAGE_FREE_DELAY_NS\|ALLOCATION_DELAY_CYCLES\|TRIAL_COUNT\|REFILL_BATCH_SIZE" \
       /home/hp/lpe-study/InfinityCore/slab/CVE-2026-97941-arch.c | head
   grep -n "set_mempolicy\|MPOL_BIND\|SCHED_IDLE" \
       /home/hp/lpe-study/InfinityCore/slab/CVE-2026-97941-arch.c | head
   ```

5. Optional, if you have a disposable VM with two NUMA nodes: run the PoC and
   watch `dmesg -w` for the GPF. (Do not do this on a machine you care
   about; the PoC deliberately panics.)
6. Exercise: write down three *different* ways you could try to defeat the
   `LIST_POISON` validation and reach a write primitive. For each, name the
   state you must win before the next allocation (this is exactly the kind of
   thinking chapter 14's method produces).

## Checkpoint

1. What exactly does the optimistic cmpxchg in `__slab_try_return_freelist()`
   verify, and what state does it *not* verify?
2. Walk through the ABA: which three operations make `{freelist, counters}`
   look unchanged while `slab_list` ends up on two lists?
3. Why does the panic happen on the *next* allocation rather than in the
   removal that corrupted the list?
4. Why does the fix keep the cmpxchg optimistic but still become correct?
5. Which environment properties (CPU count, NUMA mapping, command line,
   syscalls) are hard requirements for the PoC, and why can't you just spray
   harder on a single-node VM?
6. This is the only bug in the set without an LPE chain. In the vocabulary of
   chapter 14 §7, at which question did it stop — and what would the answer
   have to be to continue?

---

That closes the set: six bugs, four subsystems, four endgames (RB-tree write,
control-flow hijack, OOB write into a cred, page-cache overwrite) — and one
crash. You now have the full method: find the lifetime, ask who else points at
the object, find the kernel's own writes on the freed memory, build an oracle
for every stage, reclaim with an object whose geometry you chose, and only
then decide what your target's policy lets you do with it.
