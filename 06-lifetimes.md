# Chapter 6 — Who frees what, and when

Goal of this chapter: a precise map of every cleanup event around our two
objects. After this chapter you should be able to point at the exact line that
frees the timer object, the exact line that removes the tree node, and explain
why the two can happen in the wrong order.

## 1. The two objects, again

From chapters 3 and 4:

- **Object** `O` = `struct k_itimer` (slab `posix_timers_cache`). Lives on
  `signal->posix_timers` (process-wide list). Stores `it.cpu.pid` and
  `it.cpu.head`.
- **Node** `N` = `O->it.cpu.node`, queued in some
  `task->posix_cputimers.bases[2].tqhead` RB tree.

They belong to different lifetimes. There are four cleanup events that touch
them: two from "the thread/process is going away", one from "the zombie is
being reaped", and one from "exec succeeded".

## 2. Event 1 — `do_exit`: a thread stops running

Relevant part of `do_exit` (kernel/exit.c:952–975):

```c
	exit_signals(tsk);  /* sets PF_EXITING */
	...
	group_dead = atomic_dec_and_test(&tsk->signal->live);
	if (group_dead) {
		...
#ifdef CONFIG_POSIX_TIMERS
		hrtimer_cancel(&tsk->signal->real_timer);
		exit_itimers(tsk);
#endif
	}
```

Read the condition carefully: **timers are destroyed only when the *last*
thread of the thread group exits.** A single thread dying while others remain
does not touch the process's timers — that's how timers survive normal thread
churn.

Also note what `do_exit` does *not* do: it does not call
`posix_cpu_timers_exit`. The per-thread timer *queues* are not cleaned here.
Queue cleanup happens at reap time (Event 3).

For our bug this matters twice: the execing thread must be the last live
thread when it dies (in our sequence it is, because `de_thread` killed
everyone else), and its task struct must stay around after death for the
queues to still exist.

## 3. Event 2 — `exit_itimers`: destroying the objects

`exit_itimers(tsk)` (kernel/time/posix-timers.c:1085–1121):

```c
	/* Clear restore mode for exec() */
	tsk->signal->timer_create_restore_ids = 0;
	if (hlist_empty(&tsk->signal->posix_timers))
		return;

	/* Protect against concurrent read via /proc/$PID/timers */
	scoped_guard (spinlock_irq, &tsk->sighand->siglock)
		hlist_move_list(&tsk->signal->posix_timers, &timers);

	/* The timers are not longer accessible via tsk::signal */
	hlist_for_each_entry_safe(timer, next, &timers, list) {
		scoped_guard (spinlock_irq, &timer->it_lock)
			posix_timer_delete(timer);
		posix_timer_unhash_and_free(timer);
		cond_resched();
	}
```

So for each timer: `posix_timer_delete()` (which invalidates `it_signal`,
unlinks from the ID hash, and calls the clock's `timer_del` — for us
`posix_cpu_timer_del`), then `posix_timer_unhash_and_free()` which drops the
last reference and ends in:

```c
void posixtimer_free_timer(struct k_itimer *tmr)     /* posix-timers.c:442 */
{
	put_pid(tmr->it_pid);
	if (tmr->sigq.ucounts)
		dec_rlimit_put_ucounts(tmr->sigq.ucounts, UCOUNT_RLIMIT_SIGPENDING);
	kfree_rcu(tmr, rcu);                          /* deferred free! */
}
```

Two things to hold on to:

- The object is freed with **`kfree_rcu`**: the memory becomes "logically
  freed" immediately, but the actual `kfree` runs only after an RCU grace
  period. Until then the bytes may still be intact; afterwards they can be
  handed to any new allocation. Both phases matter for the exploit (reading
  stale bytes / writing made-to-measure bytes).
- `exit_itimers` is called from `do_exit` **when the last thread exits** and
  from successful `execve` (line 1213). In our failure sequence it has not run
  yet at the time the queue cleanup is skipped — remember this.

## 4. `posix_cpu_timer_del`: the dequeue that depends on a lookup

Here is `posix_cpu_timer_del` (kernel/time/posix-cpu-timers.c:574–603):

```c
static int posix_cpu_timer_del(struct k_itimer *timer)
{
	struct task_struct *p;
	unsigned long flags;
	int ret = 0;

	p = timer_lock_sighand(timer, &flags);

	if (likely(p)) {
		if (timer->it.cpu.firing) {
			timer->it.cpu.firing = false;
			ret = TIMER_RETRY;
		} else {
			disarm_timer(timer, p);       /* the only dequeue */
		}
		unlock_task_sighand(p, &flags);
	}

	if (!ret) {
		put_pid(timer->it.cpu.pid);
		timer->it_status = POSIX_TIMER_DISARMED;
	}
	return ret;
}
```

Everything hinges on `timer_lock_sighand` (523–566). It resolves the task:

```c
	for (;;) {
		struct task_struct *t = pid_task(timer->it.cpu.pid, type);

		/* Fail if the task cannot be found. */
		if (!t)
			break;
		/* Try to lock the task's sighand */
		if (lock_task_sighand(t, flags))
			return t;
	}
```

and if it never found a task:

```c
	smp_rmb();
	WARN_ON_ONCE(ctmr->head || timerqueue_node_queued(&ctmr->node));
	return NULL;
```

Notice: when the lookup fails, `posix_cpu_timer_del` **skips `disarm_timer`
entirely** and still reports success (`ret = 0`). `disarm_timer` (451–462) is
the only thing that would call `cpu_timer_dequeue()` — the only place that
removes the node from the tree. So:

> A timer whose task lookup fails is freed **without its node being
> dequeued.**

The kernel knows. The comment above `timer_lock_sighand`
(posix-cpu-timers.c:464–522) describes this entire CVE, written by the
developers themselves:

> exec() works slightly differently. The task which exec()'s terminates all
> other threads in the thread group and runs __exit_signal() on them. ...
> If a non-leader thread exec()'s this can end up in the following scenario:
>
> ```
> CPU0                                CPU1
> // Returns old leader
> p = pid_task(pid, pid_type);        de_thread()
>                                     switch_leader()      [*]
>                                     release_task(old leader)
>                                       __exit_signal()
>                                       old_leader->sighand = NULL;
> // Returns NULL
> sighand = lock_task_sighand(p)
> ```
>
> That's problematic for several functions:
>
> - posix_cpu_timer_del(): If the timer is still enqueued on the task the
>   underlying k_itimer will be freed which results in a UAF in
>   run_posix_cpu_timers() or on timerqueue related add/delete operations.

(\[*] `switch_leader()` in the comment is the old name of what the current
code calls `exchange_tids()`.)

And the `WARN_ON_ONCE` has its own comment: *"If the timer is still enqueued,
warn. ... This should never happen!"* — the kernel can detect the bad state,
but at that point it can only warn; the object is freed anyway.

## 5. Event 3 — `release_task`: the reap, where nodes are dequeued

`release_task` (kernel/exit.c:248) is called when the parent finally waits for
the zombie (and by `de_thread` for the old leader). Inside `__exit_signal`
(158–225):

```c
	spin_lock(&sighand->siglock);
#ifdef CONFIG_POSIX_TIMERS
	posix_cpu_timers_exit(tsk);
	if (group_dead)
		posix_cpu_timers_exit_group(tsk);
#endif
```

`posix_cpu_timers_exit` (posix-cpu-timers.c:636–643) → `cleanup_timers` →
`cleanup_timerqueue` on each of the three bases:

```c
static void cleanup_timerqueue(struct timerqueue_head *head)
{
	struct timerqueue_node *node;
	struct cpu_timer *ctmr;

	while ((node = timerqueue_getnext(head))) {
		timerqueue_del(head, node);
		ctmr = container_of(node, struct cpu_timer, node);
		ctmr->head = NULL;
	}
}
```

This path **never looks up a task**. It takes the tree head that lives in the
task being reaped and pulls the leftmost node out until the tree is empty.
Whatever address the tree holds, it dereferences — the tree is the only
authority.

`posix_cpu_timers_exit_group` does the same for the process-wide queues
(`signal->posix_cputimers`) when the last thread is reaped.

## 6. Event 4 — successful exec (fs/exec.c:1209–1215)

After `exec_mmap` succeeds, `begin_new_exec` does:

```c
	spin_lock_irq(&me->sighand->siglock);
	posix_cpu_timers_exit(me);      /* direct: node removed, no lookup */
	spin_unlock_irq(&me->sighand->siglock);
	exit_itimers(me);               /* object freed (lookup may fail) */
	flush_itimer_signals();
```

The order is the whole trick: **direct dequeue first (works without pid
lookup), object free second.** Even though the pid lookup inside
`posix_cpu_timer_del` fails at this point (chapter 5!), the node is already
gone, so the failure is harmless.

On the exec-failure path this block is skipped (it sits after `exec_mmap`),
and the task dies instead. Its death will free the object (`exit_itimers`)
**but nothing will have dequeued the node.** The node waits for Event 3 — the
reap — which happens later, on a different task, after the object is gone.

## 7. The asymmetry table

| event | object (`k_itimer`) | node (tree) | needs pid lookup? |
|---|---|---|---|
| `timer_delete()` | freed | dequeued | yes |
| `do_exit` (last thread) | freed via `exit_itimers` | **not touched** | lookup used, may fail → skip |
| reap (`release_task`) | not touched | dequeued via `cleanup_timerqueue` | **no** |
| exec success | freed | dequeued (direct) | lookup fails but node already gone |

The bug is the row pair "do_exit" + "reap": one event frees the object without
touching the node, a later event touches the node unconditionally, and the
only function that would have kept them consistent (the pid lookup) cannot
work anymore.

## 8. `kfree_rcu` in one picture

```
   kfree_rcu(O)                 grace period                 actual kfree
        |                            |                             |
        v                            v                             v
  O unlinked logically       RCU readers drained            memory reusable
  bytes still look valid     bytes still intact             (or already reused)
        |<----- window A ----->|<---------- window B -------->|
```

The exploit's UAF happens somewhere in windows A/B: at reap, `timerqueue_del`
will read `node.__rb_parent_color`, `rb_left`, `rb_right` and write through
them. The attacker's goal is to control *what those bytes say* by the time
that read happens.

## Hands-on

1. **Zombie experiment.** Run this and watch the child stay a zombie for 5
   seconds (in another terminal: `ps -o pid,stat,cmd -p <child pid>`):

```c
/* gcc -o zombie zombie.c */
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void)
{
	pid_t p = fork();
	if (p == 0) _exit(0);
	printf("child %d exiting; sleeping 5s before reap...\n", p);
	sleep(5);
	waitpid(p, NULL, 0);
	printf("reaped\n");
	return 0;
}
```

   While it is a zombie, `task_struct` still exists (with the timer queues).
   The `k_itimer`, however, was already freed at exit. Different lifetimes in
   the same story.

2. Read and annotate: `exit_itimers`, `posix_timer_delete`,
   `posixtimer_free_timer`, `posix_cpu_timer_del`, `timer_lock_sighand`,
   `disarm_timer`, `cleanup_timerqueue`, `posix_cpu_timers_exit`.
3. Find the huge comment block at posix-cpu-timers.c:464–522 and mark which
   sentence corresponds to which row of the asymmetry table.
4. Fill the state table from chapter 7's hands-on with this chapter's events.

## Checkpoint

1. Why are process timers freed only when the *last* thread of the group
   exits, and why is that convenient for the exploit here?
2. What exactly makes `posix_cpu_timer_del` skip `disarm_timer()`? Quote the
   `WARN_ON_ONCE` line that "detects" the state.
3. Which cleanup function dequeues nodes *without any lookup*, and from whose
   records does it take the tree head?
4. On the successful-exec path, why is the failing pid lookup harmless?
5. Where do the node's bytes live after `kfree_rcu` — and who can still reach
   them?
