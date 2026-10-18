# Chapter 16 — mincore and the page-table walker's leaked retry (CVE-2026-89754)

Goal of this chapter: leave the world of task objects and enter the **memory
management** side. The bug is not a lifetime bug at all — it is a *state
machine* bug. The kernel's page-table walker keeps a control variable,
`walk->action`, and one code path forgets to reset it, so a retry requested at
one level is replayed at the level above. The victim is `mincore()`, whose
result cursor then keeps advancing past its one-page temporary buffer and
writes 40 bytes into whatever physical page sits next.

Material: `InfinityCore/mm/README.md` and `InfinityCore/mm/CVE-2026-89754-ubuntu.c`.
Target: Ubuntu 26.04, `7.0.0-30-generic`. Introduced by `3b89863c3fa4`, fixed
by `aedf2efd1897`.

## 1. Background: walking page tables

Chapter 5 mentioned that each process has an `mm_struct` holding page tables.
A page table is a **tree**, and on x86-64 the levels are:

```
PGD → P4D → PUD → PMD → PTE → physical page
```

with one PUD entry covering 1 GiB and one PMD covering 2 MiB (512 PTEs of
4 KiB). The kernel does not want every subsystem to re-implement tree
traversal, so `mm/pagewalk.c` provides the **walker**: you register callbacks
(`pmd_entry`, `pte_entry`, `pte_hole`, ...) and the walker calls them level by
level.

The callbacks talk back through one shared field, `walk->action`:

- `ACTION_SUBTREE` — default; keep descending;
- `ACTION_AGAIN` — "the entry I just looked at changed underneath me; inspect
  it again".

`ACTION_AGAIN` exists because page tables can change under you: another thread
calls `madvise(MADV_DONTNEED)` and a PTE table that was present a moment ago is
being freed. When the walker cannot map the PTE table below a PMD
(`pte_offset_map_lock()` returns `NULL`), the callback requests the retry — a
perfectly valid, expected protocol.

And `mincore(start, len, vec)` is the syscall that reports, for each page of a
mapping, whether it is resident in RAM: **one byte of output per page**, in a
user buffer. To do this in bounded kernel memory, it processes the range in
chunks of 4096 pages and accumulates results in a single temporary kernel page
(`__get_free_page(GFP_USER)`), copying to user space chunk by chunk. Its
callback advances a cursor: `walk->private += nr` (bytes written so far).

## 2. The bug

The vulnerable retry path looks like this (simplified from the writeup):

```c
static int walk_pmd_range(...)
{
    pmd = pmd_offset(pud, addr);
    do {
again:
        next = pmd_addr_end(addr, end);
        if (pmd_none(*pmd)) {
            ...
            else if (ops->pte_hole)
                err = ops->pte_hole(addr, next, depth, walk);
            if (err)
                break;
            if (!has_install)
                continue;                     // <-- skips the reset below
        }

        walk->action = ACTION_SUBTREE;        // reset happens only here

        ...
        if (walk->action == ACTION_AGAIN)
            goto again;
    } while (pmd++, addr = next, addr != end);

    return err;
}
```

Sequence that breaks it:

1. `mincore_pte_range()` sees a present PMD, tries to map the PTE table,
   fails because `MADV_DONTNEED` is reclaiming it → sets `ACTION_AGAIN`.
2. Back in `walk_pmd_range()`, `goto again` runs. This second inspection
   now sees `pmd_none(*pmd)` (the table got removed), so it calls the
   `pte_hole` callback and takes the `continue` — **never reaching the
   `walk->action = ACTION_SUBTREE` reset**.
3. `walk_pmd_range()` returns to `walk_pud_range()`, which checks the same
   shared field:

   ```c
   err = walk_pmd_range(pud, addr, next, walk);
   ...
   if (walk->action == ACTION_AGAIN)
       goto again;                            // <-- whole PUD walked twice
   ```

   The stale `ACTION_AGAIN` makes the PUD walker redo the **entire 1 GiB
   range** from its start — and `addr` has not advanced, so the `mincore`
   callbacks run again and the result cursor advances *again*.

4. `mincore`'s temporary buffer is exactly one page. If the first pass filled
   it, the second pass writes at `tmp + 4096, tmp + 4097, ...` — an
   out-of-bounds write into the physical page adjacent to the buffer.

The fix (`aedf2efd1897`) is beautifully small: move
`walk->action = ACTION_SUBTREE` to immediately after each `again:` label, so
*every* retry starts from a known state. Lesson: state that crosses recursion
levels must be re-initialized at every retry point, not just on the common
path.

## 3. The exploit

### 3.1 Controlling the overflow: 8 ones + 32 zeros

The OOB write repeats the *second PUD chunk* of a `mincore` call. The PoC maps
a 4 GiB region and arranges one 4096-page query to straddle a PUD boundary:
4056 pages in the first PUD, 40 pages in the second. It then sets residency so
that those 40 pages produce exactly:

```
8 bytes of 0x01   (pages 0..7 are resident)
32 bytes of 0x00  (pages 8..39 are not)
```

Pages beyond the query (40..511 of the PMD) are kept resident so the PTE table
gets repopulated and the race can repeat. A reclaimer thread loops:
re-fault pages, `MADV_DONTNEED` the whole 2 MiB → present-PMD → none →
`ACTION_AGAIN` → leaked retry → 40 bytes written past the buffer.

Then look at `struct cred` (target: 184 bytes):

```c
struct cred {
    atomic_long_t usage;   // offset 0x00, 8 bytes
    kuid_t uid;            // offset 0x08
    kgid_t gid;
    kuid_t suid;
    kgid_t sgid;
    kuid_t euid;
    kgid_t egid;
    kuid_t fsuid;
    kgid_t fsgid;          // last of 8 x 4-byte IDs, ends at 0x27
    ...
} __randomize_layout;
```

The 40-byte pattern hits exactly the first 40 bytes of a `cred`:
`usage = 0x0101010101010101` (a huge positive refcount — the credential will
not be freed) and `uid..fsgid = 0` — root for real and effective IDs. No fake
pointer is needed; the kernel's own write lands on the right fields.

### 3.2 Getting X, then Y: physical page adjacency

The overflow writes into the page **physically after** the temporary `mincore`
page. So the PoC must arrange: X = `mincore`'s temp page, Y = X + 4 KiB = a
page that becomes a `cred` slab.

1. **Reserve the pair.** It creates 4000 pipes, fills and drains them, and
   plays a splice dance that leaves two live pipe buffers in `[Y, X]` order.
   Draining frees Y then X; because of the per-CPU page list's LIFO return,
   the *next* two allocations receive X and then Y. (This is the same idea as
   the pipe→AIO reclaim in chapter 13, aimed at two pages instead of one.)
2. **Hold X.** A long `mincore()` over a 4 GiB mapping allocates X as its
   temporary page and holds it for the whole walk.
3. **Make Y a cred slab.** First prewarm: 256 workers call `setuid()` with
   their *current* UID — in this kernel `setuid` still runs
   `prepare_creds()`/`commit_creds()`, filling existing credential slabs.
   Also, opening and closing `/proc/self/comm` shapes the cache used for the
   LSM security blob. Then, with X held, 240 workers each call `setuid()` on
   the CPU running `mincore`; existing slabs are full, so the first new slab
   page allocated consumes Y *in the credential cache*.
4. **Fill and aim.** Slab freelist randomization means the PoC cannot pick a
   slot; instead it keeps enough corrupted candidates alive to fill the whole
   page and ensures the worker whose object lands at **offset 0** of Y is among
   them — because the 40-byte overflow hits exactly `Y + 0x00`.

### 3.3 Repeat until root

Attack loop: run the racing `mincore()` again (which reclaims X as temp page
again), let the reclaimer thread produce the double walk, and the 8×`01` +
32×`00` lands in the first live `cred` at `Y+0`. Every target worker polls
`getuid()`/`geteuid()`; the first whose IDs are zero wins an atomic claim and
`execve`s `/bin/bash -p -i`. The corrupted `cred` stays referenced (`usage` is
huge) so nothing frees it mid-flight.

## 4. What this chapter adds to your toolbox

| technique | why it generalizes |
|---|---|
| retry state across levels | when callbacks share a state field through recursion, look for paths that return *without re-initializing it* — the bug class survives in many walkers/iterators |
| race a state transition, not a lifetime | here the race window is "present PMD becomes none"; the wanted retry/leakage is deterministic once the interleaving happens |
| OOB **offset math** | determine the overflow size from the units: 4096-page chunk − 4056-page first PUD = 40 bytes. Real target layouts fall out of simple arithmetic |
| physical PCP ordering | freeing pages in order X,Y returns them in reverse for the next allocations — a cheap way to get two adjacent pages |
| `setuid()` as a slab filler | syscalls that allocate `cred` on *every* call (even no-op ones) are a controllable spray of 184-byte objects |
| benign-field corruption | instead of replacing a pointer, write to the refcount + IDs directly; fewer moving parts, no fake object required |

## Hands-on

1. Read `InfinityCore/mm/README.md` §"Root Cause" — find the `goto again` in
   `walk_pmd_range` and answer: which single branch skips the reset?
2. See the fix in the local tree (the `linux/` checkout is newer and fixed):

   ```sh
   grep -n "again:\|walk->action = ACTION_SUBTREE" /home/hp/lpe-study/linux/mm/pagewalk.c
   ```

   Lines 128–129 and 197–198: the assignment now sits directly under the
   label. Compare with the vulnerable diff in the README.
3. Find the other two actors:

   ```sh
   grep -n "reclaim_pt" /home/hp/lpe-study/linux/mm/madvise.c
   grep -n "mincore_unmapped_range\|walk->private" /home/hp/lpe-study/linux/mm/mincore.c
   ```

   `reclaim_pt = true` is what lets `MADV_DONTNEED` free empty PTE tables; the
   `walk->private` cursor is the shared pointer that overflows.
4. In the PoC, confirm the geometry is arithmetic, not magic:

   ```sh
   grep -n "OVERFLOW_BYTES\|FIRST_PUD_PAGES\|SECOND_PMD_PAGES" \
       /home/hp/lpe-study/InfinityCore/mm/CVE-2026-89754-ubuntu.c
   ```

   Verify: `4096 - 40 = 4056` and that `FIRST_PUD_PAGES * 4096` is
   `1 GiB - 160 KiB`.

5. Experiment (safe, in userspace): write a 20-line C program that `mmap`s
   four pages, touches two, calls `mincore()`, and prints the four bytes.
   You have now personally used the syscall whose cursor this bug overran.

## Checkpoint

1. What are `ACTION_SUBTREE` and `ACTION_AGAIN` for, and why does the walker
   need a retry state at all?
2. Which exact branch made `walk_pmd_range()` return with a stale
   `ACTION_AGAIN`, and where did the fix move the reset to?
3. Why does the second walk of the PUD overflow the buffer by 40 bytes and not
   by 4096?
4. Why is the *first* 8-byte word of the pattern `0x01` instead of `0x00`?
   What would break if it were zero?
5. Why must X be "held" by a long `mincore()` before Y is turned into a cred
   slab?
6. This exploit does not fake a `cred` pointer anywhere. Why is the direct
   field overwrite simpler than the chapter 11–12 approach — and what does it
   still have in common with our bug?
