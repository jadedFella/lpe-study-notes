# Chapter 9 — The transfer: a dangling node in a live task

Goal of this chapter: after the reap of chapter 8, the exploit performs one more
small step and ends up holding something much more useful than the original
UAF: a dead `k_itimer` object whose node is still *linked in the timer queue of
a live, sleeping thread*. This chapter is about how that transfer works, why
the kernel lets it happen silently, and what the kernel will do with the node
afterwards.

Reference code: `kernel/time/posix-cpu-timers.c` and
`include/linux/posix-timers.h` from the pre-fix tree, `lib/timerqueue.c`, and
the PoC regions named below.

## 1. Where chapter 8 left us

At the end of chapter 8 the parent has just reaped the victim. The reap ran
`cleanup_timerqueue()` on the zombie's SCHED queue
(`posix-cpu-timers.c:605`):

```c
	while ((node = timerqueue_getnext(head))) {
		timerqueue_del(head, node);
		ctmr = container_of(node, struct cpu_timer, node);
		ctmr->head = NULL;
	}
```

Two things happened, *because* one of the 392 candidate timers had reused the
victim's freed slot (`allocate_oracle_candidates`, chapter 8 §8). Let us call
that candidate `C_w` — it belongs to oracle worker `w`, who is **alive and
sleeping**.

1. `timerqueue_del()` (lib/timerqueue.c:56) erased the node from the
   *zombie's* tree. As its last act it calls `RB_CLEAR_NODE(&node->node)`,
   which sets `node.__rb_parent_color = (unsigned long)node` — the encoding
   for "this node is not in any tree".
2. `ctmr->head = NULL` wrote into `C_w` (the live object!): `C_w`'s timer now
   claims **`head == NULL`**, i.e. "not queued anywhere".

But `C_w`'s node is still exactly where `timer_settime()` put it: linked as the
root/leftmost of **worker `w`'s live SCHED timerqueue**
(`task->posix_cputimers.bases[CPUCLOCK_SCHED].tqhead`). The two halves of the
kernel's bookkeeping now disagree:

| what says | "node location" | "head" |
|---|---|---|
| worker `w`'s tqhead | points at the node (root, leftmost) | — |
| `C_w->it.cpu.node` | claims unlinked (`RB_CLEAR_NODE`) | — |
| `C_w->it.cpu.head` | — | `NULL` ("not queued") |

The zombie's tree was cleaned correctly; the *live* tree was not touched. That
mismatch is the "transfer": the UAF has moved from a process that is about to
disappear into a thread that keeps existing.

## 2. The delete that should have disarmed — and doesn't

The next step in `run_exploit_attempt()` is `delete_oracle_candidates()`
(PoC 426–438):

```c
	for (unsigned int i = 0; i < oracle->thread_count; i++) {
		...
		if (timer_delete(worker->candidate))
			return -1;
		...
	}
```

For every candidate, `timer_delete` ends up in `posix_cpu_timer_del()`
(posix-cpu-timers.c:574):

```c
	p = timer_lock_sighand(timer, &flags);

	if (likely(p)) {
		if (timer->it.cpu.firing) {
			timer->it.cpu.firing = false;
			ret = TIMER_RETRY;
		} else {
			disarm_timer(timer, p);
		}
		unlock_task_sighand(p, &flags);
	}
```

For `C_w` everything looks normal:

- `timer_lock_sighand()` (523) looks up `it.cpu.pid` → worker `w` is alive → it
  locks the worker's sighand and proceeds. (No `WARN_ON_ONCE` — see §5.)
- `it.cpu.firing` is false: nobody collected this timer, because worker `w` has
  not run since its candidate was armed. CPU-time timers only advance while
  the thread runs, so this is *deterministic*, not lucky: the node cannot have
  fired.

Then `disarm_timer()` runs (453):

```c
static void disarm_timer(struct k_itimer *timer, struct task_struct *p)
{
	struct cpu_timer *ctmr = &timer->it.cpu;

	if (!cpu_timer_dequeue(ctmr))
		return;
	...
}
```

and `cpu_timer_dequeue()` (include/linux/posix-timers.h:81) opens with:

```c
	if (cpu_timer_queued(ctmr)) {          /* !!ctmr->head */
		timerqueue_del(ctmr->head, &ctmr->node);
		ctmr->head = NULL;
		return true;
	}
	return false;
```

`ctmr->head` is `NULL` (step 1 of §1), so `cpu_timer_dequeue()` **returns
false without touching the tree**. `disarm_timer()` returns immediately. The
node is never removed from worker `w`'s live queue.

Back in `posix_cpu_timer_del()` nothing else happens: `put_pid()`, set
`it_status = POSIX_TIMER_DISARMED`. The object is now eligible for release,
and when the last reference goes away (`posix-timers.c:443`):

```c
void posixtimer_free_timer(struct k_itimer *tmr)
{
	put_pid(tmr->it_pid);
	...
	kfree_rcu(tmr, rcu);           /* :447 */
}
```

So the final state is this:

```
worker w's tqhead ──► +0xe0 node (leftmost/root)     [kernel still points at it]
                        │
                        ▼
                    freed k_itimer object            [kfree_rcu pending]
                        it.cpu.head    = NULL        [written by the reap]
                        node "unlinked" marker       [written by timerqueue_del]
```

The kernel has freed the object *while still pointing at it from a live
thread's queue*. That is the second, deliberate UAF — the one the exploit will
build on.

## 3. Why this is much better than the plain trigger

Compare the two dangles:

| | chapter 7–8 UAF | after the transfer |
|---|---|---|
| lives in | a zombie that will be reaped | a live thread's queue |
| triggered by | the reap (one shot) | the worker burning CPU: **on demand** |
| readable/writable by | nobody | whichever object reuses the slot |

From here on, the exploit is no longer racing anyone. Worker `w` sleeps until
`run_stage1()` wakes it (chapter 10), and while it sleeps the exploit can:

- free the object's whole slab page,
- get that page handed back to userspace (an AIO ring / anonymous mapping),
- fill it with chosen bytes.

When worker `w` then runs, it will walk its CPU timer queue, find the node, and
interpret *our bytes* as a `struct cpu_timer`:

| offset (in the object) | field | read/written when |
|---|---|---|
| `+0xf8` | `node.expires` | compared against the sampled CPU time |
| `+0x120` | `firing` | written `true` when collected |
| `+0x128` | `handling` | written = `current` (a task pointer!) |
| `+0x100` | `head` | decides whether dequeue touches the tree |
| `+0x110..0x127` | `elist` | linked into the local firing list |
| `+0xe0/+0xe8/+0xf0` | node links | used by `timerqueue_del` |
| `+0x40` / `+0x30` | `it_lock` / validity word | taken by the handler |

Every one of those fields is in the freed 384-byte object. The kernel is about
to do *algorithmic work* using memory that userspace owns. Chapters 10–12 make
that work for us; chapter 13 explains how the page gets back to us.

## 4. What the kernel "thinks" while the node is dangling

Two quick observations that explain the silence around all of this:

- The reap's writes left the node *tagged* unlinked (`RB_CLEAR_NODE`), which
  matches what `head == NULL` claims. Nothing contradicts anything — from the
  kernel's point of view `C_w` is simply an armed-looking timer that is not
  queued.
- The live tree's root pointer is never compared against the node's own tags.
  Timers are found by walking the tree, not by asking nodes; so the walk
  continues to return the node as the leftmost element even though the node
  says "I am not here".

This is the same theme as chapter 4: **the tree and the node carry redundant
state, and the kernel trusts whichever copy is convenient.** The exploit
between the two copies.

## 5. Why there is no warning (the `WARN_ON_ONCE` in the path)

`timer_lock_sighand()` ends with (posix-cpu-timers.c:564):

```c
	smp_rmb();
	WARN_ON_ONCE(ctmr->head || timerqueue_node_queued(&ctmr->node));
	return NULL;
```

but that code only runs when `pid_task()` *fails*. Worker `w` is alive, so the
lookup succeeds and the warning is not reached. And even if it were reached,
both conditions are false on purpose:

- `ctmr->head` is `NULL` (the reap wrote it),
- `timerqueue_node_queued()` is `!RB_EMPTY_NODE(&node->node)`
  (include/linux/timerqueue.h:33) and the node *claims* empty because
  `timerqueue_del()` ran `RB_CLEAR_NODE` on it.

The warning is designed to catch "still queued while being destroyed". The
exploit arranged for the object to be *destroyed while still queued but
labelled unqueued*, which is invisible to every sanity check in the path.

## 6. One more detail: the first `timerqueue_del` wrote into the node too

When the reap called `timerqueue_del(zombie_head, node)` on the *live* `C_w`
node, that call also did a tiny bit of unauthorized bookkeeping. `rb_erase`
looks at the node's children (`rb_left`, `rb_right`). For a freshly armed
candidate in an otherwise empty per-worker queue, both are `NULL`, so the erase
took the trivial branch and:

- rewrote the zombie's root pointer (its own tree — correct),
- ran `RB_CLEAR_NODE(&node->node)` → `node.__rb_parent_color = &node` (into
  `C_w`),
- potentially rewrote the "parent" child pointer if the node had had a parent
  — it doesn't; each worker's queue holds exactly one candidate.

That "exactly one timer per worker" property matters for the exploit's
stability: the cross-tree deletion cannot corrupt a *second* node, because
there is none in that queue.

## Hands-on

1. Read PoC 426–438 (`delete_oracle_candidates`). Then read, in
   `posix-cpu-timers.c`, lines 453–461 (`disarm_timer`), 574–600
   (`posix_cpu_timer_del`), and `include/linux/posix-timers.h:69–94`
   (`cpu_timer_enqueue/dequeue`).
2. Trace by hand: which exact line stops the dequeue? Which line had earlier
   written the value it reads? Which function wrote that value (chapter 8 §9),
   and why did *that* function not remove the node itself?
3. Answer: what would happen if worker `w` burned ≥20 ms of CPU time between
   `allocate_oracle_candidates()` and `delete_oracle_candidates()`? Walk the
   collect path (`collect_timerqueue`, posix-cpu-timers.c:864) and describe
   which of the two candidate properties (`firing`, `head`) would change, and
   how `posix_cpu_timer_del` would react (`TIMER_RETRY`, line 585–592). Why
   does the exploit keep all workers asleep until `run_stage1()`?
4. Answer: after the transfer, which of the following do you expect to be true
   *from the kernel's point of view*? Justify with the code:
   (a) the node is queued in worker `w`'s queue;
   (b) `C_w`'s timer is armed;
   (c) `C_w`'s timer is queued.
5. Extra: find `timerqueue_node_queued()` and `RB_EMPTY_NODE()` in the headers
   and write the exact predicate the kernel uses for "this node is in a tree".

## Checkpoint

1. Name the two writes the reap makes into the live candidate object, and name
   the function that makes each.
2. Why does `disarm_timer()` do nothing when the candidate is deleted?
3. Where does the object get freed, and why is it safe for the exploit to keep
   using its memory afterwards?
4. Why is the "exactly one candidate per worker" property important for the
   reap's `rb_erase` on a foreign tree?
5. What does the exploit gain by transferring the dangling node from the
   zombie to a live worker?
