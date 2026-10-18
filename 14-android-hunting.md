# Chapter 14 — Android, and how to hunt bugs like this yourself

Goal of this final chapter: two things. First, honest engineering advice for
moving this exploit to Android — what survives the trip and what has to be
rebuilt. Second, the reusable part: a method for *finding* bugs of this shape
instead of admiring this one. The kernel source references are still the
pre-fix tree; the Android advice is about your target's tree and config.

## Part I — Porting to Android

### 1. What transfers and what gets rebuilt

| part | portability | why |
|---|---|---|
| trigger (non-leader exec + timed fatal signal) | **portable** | pure `timer_create`/`execve`/signal semantics; chapter 7's checklist is kernel-version independent |
| dangling-node transfer (`head == NULL`) | portable *if the bug exists* | depends only on `disarm_timer`/`cleanup_timerqueue`/`posix_cpu_timer_del` shapes |
| leak (stage 1: `handling`/`elist` writes) | portable in mechanism | the collect/handler design must match; offsets change |
| RB-erase write (stage 2) | portable | `rb_erase` is generic; only offsets/aliasing change |
| heap grooming constants | **rebuild** | they encode *your* target's SLUB, RCU batching and PCP sizes |
| root pivot (setuid file) | **rebuild** | SELinux + `nosuid` mounts kill the setuid trick |

### 2. The four questions to ask an Android target, in order

1. **Does the bug exist?** The fix `acb03d388181` adds a `posixtimer_exec()`
   call right after `de_thread()` in `fs/exec.c`. On your target, find that
   call site:
   - fix present → not vulnerable (move on);
   - fix absent *and* the reworked CPU-timer code present (`it.cpu.head`,
     `collect_timerqueue` with `handling`, `disarm_timer`) → vulnerable shape.
   The rework was introduced shortly before the fix; older Android kernels with
   the classic posix CPU timer design simply do not have this bug.
2. **Can I reach the bug?** `untrusted_app` seccomp:
   - `timer_create`, `timer_settime`, `timer_delete` are commonly allowed
     (apps use timers);
   - the trigger needs `execve` (allowed) and signals via `tgkill` (allowed);
   - the *heap* part wants volume allocations. `io_setup` may be blocked —
     then drop the AIO half of the spray and use anonymous pages (the PoC
     already allocates 64000 of them) plus `memfd`/`MAP_PRIVATE` faults; the
     principle (kernel-freed page → user-mapped page) does not change.
3. **Which numbers change?** Everything layout-related:
   - `sizeof(struct k_itimer)` and the `cpu_timer` field offsets
     (`node`, `expires`, `head`, `elist`, `firing`, `handling`, validity word,
     `it_lock`);
   - `task_struct` offsets: `cred`, `real_cred`,
     `posix_cputimers.bases[...].tqhead`;
   - `cred` layout: uid fields, capability sets, `security`, `user_ns`;
   - SLUB parameters: sheaves/barns (new SLUB) or `cpu_partial` freelists
     (classic SLUB), plus slab order and objects-per-slab.
   Get the first three from the target's BTF
   (`/sys/kernel/btf/vmlinux`, or extracted from the boot image) with
   `bpftool btf dump ... format c` / `pahole -C k_itimer`. Get the last one
   from the target's `mm/slub.c` version, or by measurement with a harness
   (allocate/free timer counts in a loop while watching slab behaviour).
4. **Can I finish?** This is where Android diverges most:
   - `cred` is not enough: SELinux checks use `cred->security`
     (`struct task_security_struct`: `osid`, `sid`, enforcing state). A fake
     credential whose sid is the app's own domain changes nothing for
     protected resources. A port needs a fake blob pointing at a *permissive*
     or privileged sid — on production devices those do not exist for apps —
     or a second write to the SELinux state/AVC logic itself.
   - The setuid pivot is dead: app data dirs are mounted `nosuid`
     (`pick_staging_dir` would find no candidate), and SELinux policy does not
     allow unprivileged domains to execute setuid files on writable data.
   - Realistic endgames instead: use the same RB-erase primitive to *aim at
     another process's* `cred` slot (you pick the target address yourself —
     the primitive is a write to a value of your choice at a place of your
     choice, once you know addresses); or disable SELinux enforcement via the
     kernel's own state; or patch the `cred`s of `init`/`zygote`-spawned
     processes. All of these require additional address leaks (KASLR, text
     base, task discovery) that this Ubuntu PoC did not need.

### 3. Android-specific hardening to check on the target

| mitigation | effect on this exploit |
|---|---|
| `panic_on_warn=1` | the trigger's `WARN_ON_ONCE` (and the list double-add during stage 1) reboots the device → DoS, not LPE. Verify the WARN paths are avoided on your build (stage 1 may need a redesign). |
| `CONFIG_INIT_ON_FREE/ALLOC` | harmless here: the page is filled by *us* after reclaim, so pre-reclaim contents do not matter. |
| KASLR | the exploit is KASLR-agnostic (all addresses are leaked at runtime) — but a *new* endgame may need symbol addresses. |
| hardened usercopy | not involved: all writes are kernel→kernel (direct map writes to a physical page), not `copy_to_user`. |
| KCFI / BTI | not involved: no control-flow hijack, only data writes. |
| MTE | the writes go through the untagged direct map; the user mapping reads them normally. MTE does not stop this. |
| `CONFIG_DEBUG_LIST` **off** | changes stage-1 behaviour: the repeated `list_add_tail` no longer no-ops but self-links the entry. Capture the leak differently (the self-pointer is *already* the direct-map address; the two-phase stack/self distinction collapses). |

### 4. Port in stages, with an oracle at each stage

Do not port the whole exploit and then debug. Each stage of this exploit has a
cheap observable; build a harness per stage:

| stage | what to observe | how |
|---|---|---|
| trigger | the `WARN_ON_ONCE` in `timer_lock_sighand` ("should never happen") in dmesg; `panic_on_warn=0`, watch `dmesg -w` |
| transfer | one worker stops making progress (blocked on the fake `it_lock`) — the "winner" oracle of chapter 10 |
| leak | a kernel pointer appearing in a user page at the `handling` offset; `elist` self-pointer for the alias |
| write | the `st_uid == 0` file oracle of chapter 12 (works even before any pivot exists) |
| endgame | whatever your target's privilege model allows |

Every one of those was used by the PoC itself; they are the difference between
"it usually works" and "I know which stage failed".

## Part II — Hunting bugs like this one

### 5. The shape of the bug, abstracted

Strip away the timers and what is left is a three-part pattern:

1. **One object, two lifetimes.** The `k_itimer` is tracked by (a) a refcount
   and (b) a tree node embedded in *another task's* timer queue. Freeing the
   object does not free the tree membership, because the tree does not own a
   reference. *Ask of every object: who else points at this without holding a
   reference?*
2. **A fallible owner lookup that silently skips cleanup.** `timer_lock_sighand`
   asks "who is the owner?" via `pid_task()`; during exec that lookup can fail
   while the timer is still queued, and the code's fallback is to *warn and do
   nothing* — because "this should never happen". The state exists anyway.
3. **An identity transition in the middle.** `de_thread()` changes who the
   PIDs resolve to and reaps the leader; the exec error path afterwards can
   exit without ever taking a path that would have dequeued the node.

The exploit adds the fourth ingredient that makes it a *privilege escalation*
rather than a crash: **the stale memory is reused by something the attacker
can read and write** (chapters 9, 13), and the kernel keeps *operating* on it
(chapter 10–11).

### 6. Where to look (concrete greps)

Run these against a kernel tree and read what comes up (the pre-fix tree is a
convenient corpus for practice):

```sh
# 1. Cleanup paths guarded by "impossible" states
grep -rn "should never happen" kernel/ | grep -i "warn\|BUG"

# 2. Owner lookups whose NULL/error case skips cleanup
grep -rn "pid_task\|find_task_by_vpid" kernel/ | head

# 3. Objects freed by RCU but reachable from other structures
grep -rn "kfree_rcu" kernel/ mm/ | head

# 4. exec error paths after the commit point
grep -n "point_of_no_return\|de_thread\|begin_new_exec" fs/exec.c
```

Then for each hit ask the §5 questions. The commits that introduced and fixed
this bug (`55e8c8eb2c7b` → `acb03d388181`) are worth reading end to end as
templates: the fix is small — the lesson is *where* it had to be placed
(immediately after the identity change, before any fallible step), not what it
does.

Also useful:

- `git log -L :cleanup_timerqueue:kernel/time/posix-cpu-timers.c` — history of
  a suspicious function;
- `git log --grep=Fixes -- kernel/time/posix-cpu-timers.c` — bug-fix
  archaeology;
- syzbot dashboards for `kernel/time` and `fs/exec` — the fuzzer finds
  trigger-shaped bugs; your job is the "how do I make it useful" part;
- CVE feeds filtered by `exec` + `UAF` + `race`.

### 7. From bug to primitive (the mindset)

When you find a UAF, do not stop at "I can crash it". Ask, in order:

1. **What writes does the kernel itself perform on this object after it is
   freed?** (Here: the collect path wrote `handling`/`elist`; the tree erase
   wrote two pointers.) Algorithmic writes beat arbitrary-write gadgets.
2. **What can I control about those writes?** (Here: everything, because the
   object became a whole user page: `head`, `expires`, node links, list
   entries, lock words.)
3. **Which write lands somewhere interesting?** (Here: `rb_erase`'s
   `tmp->__rb_parent_color = pc` can target `task->cred` if the node's left
   child is `&task->cred`.)
4. **What oracle tells me the write happened?** (Here: a file's owning uid.)
5. **What converts the primitive into my goal given the target's policy?**
   (Ubuntu: setuid exec. Android: something else — §2.)

### 8. Exercises

1. **Audit exercise.** Pick any subsystem with cleanup functions
   (`kernel/time/`, `ipc/`, `fs/`). List three objects tracked in more than one
   container. For each, write: which container holds a reference, which does
   not, and what a stale pointer in the non-owning container would be used for
   if the object were freed.
2. **Pattern exercise.** Find every `WARN_ON_ONCE` in
   `kernel/time/posix-cpu-timers.c` and `kernel/time/posix-timers.c`. For each,
   write the state it claims is impossible and *construct* that state on paper
   (the bug of this book is one instance).
3. **Fuzzing exercise.** Sketch a syzkaller program that creates a per-thread
   CPU timer in a non-leader pthread, execs, and kills — and explain which
   syscalls in your sketch the Android `untrusted_app` seccomp policy would
   likely reject.
4. **Fix-reading exercise.** Fetch the fix `acb03d388181` and answer:
   why must `posixtimer_exec()` run *before* `unshare_files()` and
   `exec_mmap()`? What, specifically, would still be broken if it ran at the
   old cleanup site (after successful `exec_mmap`)?
5. **Port exercise.** Take the four questions of §2 and answer them for one
   concrete Android device you have access to (a rooted dev board or an
   emulator with a custom kernel is fine). Produce a one-page verdict: bug
   present, reachable, offsets obtainable, endgame plausible.

## Checkpoint

1. Which stages of this exploit are kernel-version independent, and which
   encode one specific allocator?
2. Why does a forged `cred` alone not grant access to protected resources on
   Android?
3. What is the single call the fix adds, and where is it placed?
4. State the three-part pattern of this bug class in one sentence each.
5. When you find a UAF, what is the first question that turns it from "crash"
   into "primitive"? Name one example from this book.
6. Which two Android mitigations would force the biggest redesigns for this
   specific exploit, and why?

---

That is the end of the book. If you have read this far: the next time you see
a `kfree_rcu` next to a `WARN_ON_ONCE` and a fallible `pid_task()`, you will
know exactly why your eyes should narrow.
